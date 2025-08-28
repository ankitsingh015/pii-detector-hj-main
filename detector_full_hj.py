import csv
import json
import re
import sys

# --------- PII Detection Utilities ----------

# Standalone PII regexes and matchers
PHONE_REGEX = re.compile(r"\b[6-9]\d{9}\b")
AADHAR_REGEX = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
# Indian passport patterns: 1 or 2 alpha + 7 digits
PASSPORT_REGEX = re.compile(r"\b([A-PR-WYa-pr-wy][0-9]{7}|[A-PR-WYa-pr-wy]{2}[0-9]{7})\b")
UPI_REGEX = re.compile(r"\b[\w\.\-]{2,}@[a-zA-Z]{2,}\b")

EMAIL_REGEX = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b")
IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

# Helper for masking
def mask_phone(val):
    return val[:2] + "XXXXXX" + val[-2:] if len(val) == 10 else "[REDACTED_PII]"

def mask_aadhar(val):
    d = re.sub(r"\D", "", val)
    return d[:2] + "XXXXXX" + d[-4:] if len(d) == 12 else "[REDACTED_PII]"

def mask_passport(val):
    if len(val) == 8:
        return val[0] + "XXXX" + val[-3:]
    if len(val) == 9:
        return val[:2] + "XXXXX" + val[-2:]
    return "[REDACTED_PII]"

def mask_upi(val):
    try:
        prefix, suffix = val.split("@", 1)
        return prefix[0] + "XXX" + "@" + suffix
    except Exception:
        return "[REDACTED_PII]"

def mask_name(val):
    parts = val.split()
    masked = []
    for p in parts:
        if len(p) > 1:
            masked.append(p[0] + "XXX")
        else:
            masked.append(p)
    return " ".join(masked)

def mask_email(val):
    try:
        local, domain = val.split("@", 1)
        if len(local) > 1:
            return local[0] + "XXX@" + domain
        else:
            return "[REDACTED_PII]"
    except Exception:
        return "[REDACTED_PII]"

def mask_address(val):
    # Mask numbers, replace with X, keep city/pincode
    return re.sub(r"\d", "X", val)

def mask_ip(val):
    # Mask last octet
    try:
        parts = val.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".XXX"
        else:
            return "[REDACTED_PII]"
    except Exception:
        return "[REDACTED_PII]"

def mask_device(val):
    return val[:2] + "XXX" + val[-2:] if len(val) > 4 else "[REDACTED_PII]"

# --------- PII Detection Logic --------------

def is_phone(val):
    return bool(PHONE_REGEX.fullmatch(val.strip()))

def is_aadhar(val):
    just_digits = re.sub(r"\D", "", val)
    return bool(AADHAR_REGEX.fullmatch(val.strip())) or (len(just_digits) == 12)

def is_passport(val):
    return bool(PASSPORT_REGEX.fullmatch(val.strip()))

def is_upi(val):
    return bool(UPI_REGEX.fullmatch(val.strip()))

def is_email(val):
    return bool(EMAIL_REGEX.fullmatch(val.strip()))

def is_ip(val):
    return bool(IP_REGEX.fullmatch(val.strip()))

def is_address(val):
    # If likely an address (street + city + pincode): has digit, comma, and 6-digit pin
    if "," in val and re.search(r"\d{6}", val):
        return True
    return False

# --------- Main Processing Logic -------------

def process_record(data_dict):
    found = {
        'phone': None, 'aadhar': None, 'passport': None, 'upi_id': None,
        'name': None, 'email': None, 'address': None, 'device_id': None, 'ip_address': None
    }
    combinatorial = set()
    redacted = dict()
    for k, v in data_dict.items():
        key, val = k.lower(), str(v)
        # Standalone PII
        if key == "phone" or is_phone(val):
            found['phone'] = val
            redacted[k] = mask_phone(val)
        elif key == "aadhar" or is_aadhar(val):
            found['aadhar'] = val
            redacted[k] = mask_aadhar(val)
        elif key == "passport" or is_passport(val):
            found['passport'] = val
            redacted[k] = mask_passport(val)
        elif key == "upi_id" or is_upi(val):
            found['upi_id'] = val
            redacted[k] = mask_upi(val)
        # Combinatorial PII
        elif key == "name":
            found['name'] = val
            redacted[k] = mask_name(val)
            combinatorial.add("name")
        elif key == "email" and is_email(val):
            found['email'] = val
            redacted[k] = mask_email(val)
            combinatorial.add("email")
        elif key == "address" and is_address(val):
            found['address'] = val
            redacted[k] = mask_address(val)
            combinatorial.add("address")
        elif key == "device_id":
            found['device_id'] = val
            redacted[k] = mask_device(val)
            combinatorial.add("device_id")
        elif key == "ip_address" and is_ip(val):
            found['ip_address'] = val
            redacted[k] = mask_ip(val)
            combinatorial.add("ip_address")
        else:
            # For other fields, check for phone, aadhar, upi in values
            if is_phone(val):
                found['phone'] = val
                redacted[k] = mask_phone(val)
            elif is_aadhar(val):
                found['aadhar'] = val
                redacted[k] = mask_aadhar(val)
            elif is_passport(val):
                found['passport'] = val
                redacted[k] = mask_passport(val)
            elif is_upi(val):
                found['upi_id'] = val
                redacted[k] = mask_upi(val)
            elif is_email(val):
                found['email'] = val
                redacted[k] = mask_email(val)
                combinatorial.add("email")
            else:
                redacted[k] = v

    # PII Decision
    is_pii = False
    # Standalone PII triggers
    for f in ['phone', 'aadhar', 'passport', 'upi_id']:
        if found[f]:
            is_pii = True
    # Combinatorial: at least 2 present
    combo_count = 0
    for f in ['name', 'email', 'address', 'device_id', 'ip_address']:
        if found[f]:
            combo_count += 1
    if combo_count >= 2:
        is_pii = True

    return redacted, is_pii

# --------- Main Program ---------------------

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <input_csv>")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"

    with open(input_csv, newline='', encoding='utf-8') as fin, \
         open(output_csv, "w", newline='', encoding='utf-8') as fout:
        reader = csv.DictReader(fin)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            record_id = row['record_id']
            try:
                data_dict = json.loads(row['data_json'])
            except Exception:
                # If not valid JSON, skip or mark as non-PII
                writer.writerow({
                    'record_id': record_id,
                    'redacted_data_json': row['data_json'],
                    'is_pii': False
                })
                continue

            redacted, is_pii = process_record(data_dict)
            writer.writerow({
                'record_id': record_id,
                'redacted_data_json': json.dumps(redacted, ensure_ascii=False),
                'is_pii': str(is_pii)
            })

if __name__ == "__main__":
    main()