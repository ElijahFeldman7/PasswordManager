# main.py
import os
import getpass
import time
from datetime import datetime, timezone
from typing import Union  

import auth
import sync
import crypto

LOCAL_VAULT_PATH = 'vault.dat'

def get_utc_from_iso(iso_string: str) -> datetime:
    """Converts a Google Drive API ISO 8601 timestamp to a UTC datetime object."""
    if iso_string.endswith('Z'):
        iso_string = iso_string[:-1] + '+00:00'
    if '.' in iso_string:
        parts = iso_string.split('.')
        ms_part_full = parts[1]
        if '+' in ms_part_full:
            ms_part, tz_part = ms_part_full.split('+')
            tz_info = f"+{tz_part}"
        elif '-' in ms_part_full:
            ms_part, tz_part = ms_part_full.split('-')
            tz_info = f"-{tz_part}"
        else:
            ms_part = ms_part_full
            tz_info = ""

        if len(ms_part) > 6:
            ms_part = ms_part[:6]
        iso_string = f"{parts[0]}.{ms_part}{tz_info}"

    return datetime.fromisoformat(iso_string)


def handle_sync(drive_service):
    """Orchestrates the cloud sync logic."""
    print("Checking cloud sync status...")
    remote_id, remote_mod_time_str = sync.find_remote_vault(drive_service)
    local_exists = os.path.exists(LOCAL_VAULT_PATH)

    if remote_id and not local_exists:
        print("Remote vault found, no local vault. Downloading...")
        sync.download_vault(drive_service, remote_id, LOCAL_VAULT_PATH)
    elif not remote_id and local_exists:
        print("Local vault found, no remote vault. Uploading...")
        sync.upload_vault(drive_service, LOCAL_VAULT_PATH)
    elif remote_id and local_exists:
        print("Both local and remote vaults exist. Comparing timestamps...")
        local_mod_time_utc = datetime.fromtimestamp(os.path.getmtime(LOCAL_VAULT_PATH), tz=timezone.utc)
        remote_mod_time_utc = get_utc_from_iso(remote_mod_time_str)
        
        print(f"  Cloud version: {remote_mod_time_utc}")
        print(f"  Local version: {local_mod_time_utc}")

        if remote_mod_time_utc > local_mod_time_utc:
            print("Cloud version is newer. Downloading...")
            sync.download_vault(drive_service, remote_id, LOCAL_VAULT_PATH)
        else:
            print("Local version is newer or the same. No download needed.")


def load_decrypted_vault(master_password: str) -> Union[dict, None]:
    """Loads and decrypts the vault from the local file."""
    if not os.path.exists(LOCAL_VAULT_PATH):
        return None

    with open(LOCAL_VAULT_PATH, 'rb') as f:
        salt = f.read(crypto.SALT_LENGTH)
        encrypted_data = f.read()
    
    key = crypto.derive_key(master_password, salt)
    return crypto.decrypt(encrypted_data, key)


def save_and_encrypt_vault(vault_data: dict, master_password: str):
    """Encrypts and saves the vault to the local file."""
    salt = os.urandom(crypto.SALT_LENGTH)
    key = crypto.derive_key(master_password, salt)
    
    encrypted_blob = crypto.encrypt(vault_data, key)
    
    with open(LOCAL_VAULT_PATH, 'wb') as f:
        f.write(salt)
        f.write(encrypted_blob)


def show_main_menu(vault_data: dict, master_password: str, drive_service):
    """Displays the main menu and handles user interaction."""
    while True:
        print("\n" + "="*20)
        print("      MAIN MENU")
        print("="*20)
        print("(L) List all services")
        print("(V) View a password")
        print("(A) Add a new password")
        print("(D) Delete a password")
        print("(S) Save and Sync to Cloud")
        print("(Q) Quit")
        choice = input("> ").lower().strip()

        if choice == 'l':
            if not vault_data['passwords']:
                print("No passwords saved yet.")
            else:
                print("\n--- Saved Services ---")
                for service in sorted(vault_data['passwords'].keys()):
                    print(f"- {service}")
        
        elif choice == 'v':
            service = input("Enter service name to view: ").strip()
            entry = vault_data['passwords'].get(service)
            if entry:
                print(f"\n--- Details for '{service}' ---")
                print(f"  Username: {entry['username']}")
                print(f"  Password: {entry['password']}")
            else:
                print(f"Service '{service}' not found.")

        elif choice == 'a':
            service = input("Enter service name (e.g., Google, Amazon): ").strip()
            username = input(f"Enter username for {service}: ").strip()
            password = getpass.getpass(f"Enter password for {service}: ")
            vault_data['passwords'][service] = {'username': username, 'password': password}
            print(f"Added entry for '{service}'. Don't forget to save!")

        elif choice == 'd':
            service = input("Enter service name to delete: ").strip()
            if service in vault_data['passwords']:
                confirm = input(f"Are you sure you want to delete '{service}'? (y/n): ").lower()
                if confirm == 'y':
                    del vault_data['passwords'][service]
                    print(f"Deleted '{service}'.")
            else:
                print(f"Service '{service}' not found.")

        elif choice == 's':
            print("Encrypting and saving vault locally...")
            save_and_encrypt_vault(vault_data, master_password)
            print("Uploading to cloud...")
            sync.upload_vault(drive_service, LOCAL_VAULT_PATH)
            print("Sync complete.")

        elif choice == 'q':
            print("Exiting.")
            break
        
        else:
            print("Invalid choice, please try again.")


def main():
    """The main entry point for the password manager application."""
    print("="*40)
    print("  Welcome to Your Secure Password Manager")
    print("="*40)
    
    drive_service = auth.get_drive_service()
    handle_sync(drive_service)

    vault_data = None
    master_password = ""

    if os.path.exists(LOCAL_VAULT_PATH):
        print("\n--- Unlock Your Vault ---")
        while vault_data is None:
            master_password = getpass.getpass("Enter your master password: ")
            vault_data = load_decrypted_vault(master_password)
            if vault_data is None:
                print("Incorrect password or corrupted vault. Please try again.")
    else:
        print("\n--- Create a New Vault ---")
        print("No local vault found. Let's create one.")
        while True:
            master_password = getpass.getpass("Enter a strong new master password: ")
            confirm_password = getpass.getpass("Confirm your master password: ")
            if master_password == confirm_password:
                if len(master_password) < 12:
                     print("Password is too short! Please use at least 12 characters.")
                else:
                    break
            else:
                print("Passwords do not match. Please try again.")
        
        vault_data = {'passwords': {}}
        save_and_encrypt_vault(vault_data, master_password)
        print("\nNew vault created and saved locally.")
        print("Uploading initial vault to the cloud...")
        sync.upload_vault(drive_service, LOCAL_VAULT_PATH)
        print("Initial sync complete.")

    print("\nVault successfully unlocked!")
    show_main_menu(vault_data, master_password, drive_service)


if __name__ == '__main__':
    main()