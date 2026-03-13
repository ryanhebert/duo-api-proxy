import os
import json
import duo_client
from dotenv import load_dotenv

# Load .env if it exists
load_dotenv()

def get_credentials():
    host = os.getenv("DUO_HOST")
    ikey = os.getenv("DUO_IKEY")
    skey = os.getenv("DUO_SKEY")

    if not all([host, ikey, skey]):
        print("Credentials missing from .env (or .env not found).")
        print("Please enter them manually for this session (they won't be saved).")
        if not host:
            host = input("Duo API Hostname (e.g., api-xxxxxxxx.duosecurity.com): ").strip()
        if not ikey:
            ikey = input("Admin API Integration Key (ikey): ").strip()
        if not skey:
            skey = input("Admin API Secret Key (skey): ").strip()
    
    return host, ikey, skey

def main():
    print("==================================================")
    print("      Duo Integration Discovery Tool")
    print("==================================================")
    
    host, ikey, skey = get_credentials()
    
    if not all([host, ikey, skey]):
        print("Error: Missing credentials. Exiting.")
        return

    try:
        # Initialize the official Duo Client
        # The library handles v1/v2/v3 signing automatically
        admin_api = duo_client.Admin(
            ikey=ikey,
            skey=skey,
            host=host
        )

        print("Fetching integrations via official Duo Client...", end="", flush=True)
        # get_integrations() uses the /admin/v1/integrations endpoint by default
        # but the library's internal logic is highly reliable.
        all_integrations = admin_api.get_integrations()
        print(" Done.")

    except Exception as e:
        print(f"\n[ERROR] Failed to fetch integrations: {e}")
        print("\nPossible reasons:")
        print("1. Incorrect Integration Key (ikey) or Secret Key (skey).")
        print("2. Your Admin API application lacks 'Grant read information' permissions.")
        print("3. Network/Proxy issues reaching Duo.")
        return

    if not all_integrations:
        print("No integrations found.")
        return

    # 1. Aggregate Types
    unique_types = sorted(list(set(i['type'] for i in all_integrations)))
    
    while True:
        print(f"\nFound {len(all_integrations)} integrations across {len(unique_types)} types.")
        print("\n--- Available Integration Types ---")
        for idx, t in enumerate(unique_types):
            print(f"{idx + 1}. {t}")
        
        print("0. Exit")
        
        try:
            choice_input = input("\nSelect a type number to inspect: ").strip()
            if not choice_input: continue
            choice = int(choice_input)
            
            if choice == 0:
                break
            if choice < 1 or choice > len(unique_types):
                print("Invalid selection.")
                continue
            
            selected_type = unique_types[choice - 1]
            
            # 2. Filter Integrations by Type
            filtered_integrations = [i for i in all_integrations if i['type'] == selected_type]
            
            while True:
                print(f"\n--- Integrations of type '{selected_type}' ---")
                for idx, integ in enumerate(filtered_integrations):
                    print(f"{idx + 1}. {integ['name']} (ikey: {integ['integration_key']})")
                
                print("0. Back to Types")
                
                sub_choice_input = input("\nSelect an integration number to view details: ").strip()
                if not sub_choice_input: continue
                sub_choice = int(sub_choice_input)
                
                if sub_choice == 0:
                    break
                if sub_choice < 1 or sub_choice > len(filtered_integrations):
                    print("Invalid selection.")
                    continue
                
                # 3. Show Details
                selected_integ = filtered_integrations[sub_choice - 1]
                print(f"\n--- Configuration for {selected_integ['name']} ---")
                print(json.dumps(selected_integ, indent=4))
                input("\nPress Enter to continue...")
                
        except ValueError:
            print("Please enter a number.")
        except KeyboardInterrupt:
            print("\nExiting.")
            break

if __name__ == "__main__":
    main()
