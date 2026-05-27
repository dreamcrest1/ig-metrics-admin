import hmac
import hashlib
import base64
from datetime import datetime, timedelta

LICENSE_SECRET = b"IG_METRICS_PRO_SECRET_2026"

def generate_key(days, tool="ig-master-suite"):
    expiry_date = datetime.now().date() + timedelta(days=days)
    expiry_str = expiry_date.strftime("%Y-%m-%d")
    
    # Compute signature with tool binding
    sig_payload = f"{expiry_str}|{tool}"
    sig = hmac.new(LICENSE_SECRET, sig_payload.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    payload = f"{expiry_str}|{tool}|{sig}"
    
    # Base64 encode
    encoded = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    return encoded, expiry_str

def main():
    print("=" * 60)
    print("=== DREAMCREST - Enterprise Universal License Key Generator ===")
    print("=" * 60)
    print("Generate secure cryptographically signed client keys.")
    print("-" * 60)
    
    print("Select Target Application:")
    print("1) IG Master Suite")
    print("2) Dreamcrest WhatsApp Sender")
    print("3) All Apps (Universal)")
    print("4) Custom Application (Enter name)")
    print("-" * 60)
    app_choice = input("Enter target app choice (1-4): ").strip()
    
    tool = "ig-master-suite"
    if app_choice == "1":
        tool = "ig-master-suite"
    elif app_choice == "2":
        tool = "whatsapp-bulk-sender"
    elif app_choice == "3":
        tool = "all"
    elif app_choice == "4":
        tool = input("Enter custom application identifier: ").strip().lower().replace(" ", "-")
        if not tool:
            print("❌ Invalid tool name!")
            return
    else:
        print("❌ Invalid target choice!")
        return

    print("-" * 60)
    print("Select key duration options:")
    print("1) 20 Days")
    print("2) 30 Days")
    print("3) 50 Days")
    print("4) 1 Year (365 Days)")
    print("5) Lifetime (Dec 31, 2099)")
    print("6) Custom duration in Days")
    print("-" * 60)
    
    choice = input("Enter duration choice (1-6): ").strip()
    
    days = 0
    if choice == "1":
        days = 20
    elif choice == "2":
        days = 30
    elif choice == "3":
        days = 50
    elif choice == "4":
        days = 365
    elif choice == "5":
        # Dec 31, 2099
        lifetime_date = datetime(2099, 12, 31).date()
        current_date = datetime.now().date()
        days = (lifetime_date - current_date).days
    elif choice == "6":
        try:
            days = int(input("Enter custom duration in days: ").strip())
        except ValueError:
            print("❌ Invalid number of days!")
            return
    else:
        print("❌ Invalid duration choice!")
        return

    if days <= 0:
        print("❌ Duration must be greater than 0 days!")
        return
        
    key, expiry_str = generate_key(days, tool)
    print("-" * 60)
    print(f"🔑 GENERATED LICENSE KEY FOR '{tool}' (Expires: {expiry_str}):")
    print("-" * 60)
    print(key)
    print("-" * 60)
    print("Copy the complete license key string above and provide it to the client.")
    print("=" * 60)

if __name__ == "__main__":
    main()
