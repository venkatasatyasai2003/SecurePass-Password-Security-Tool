import hashlib
import requests
import getpass
import string

# Function to check password strength
def password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])

    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Moderate"
    else:
        return "Weak"

# Function to check for breaches using k-Anonymity
def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError("Error fetching data from API")

    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

# Main program
if __name__ == '__main__':
    print("🔐 SecurePass: Password Strength & Breach Checker\n")

    pwd = getpass.getpass("Enter your password: ")

    # Strength Check
    strength = password_strength(pwd)
    print(f"\n🛡️ Password Strength: {strength}")

    # Breach Check
    try:
        breach_count = pwned_api_check(pwd)
        if breach_count:
            print(f"⚠️ This password has been found {breach_count} times in data breaches!")
        else:
            print("✅ This password has NOT been found in known breaches.")
    except Exception as e:
        print(f"Error checking password breaches: {e}")
