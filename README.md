import os
import secrets
import hashlib
import base58
import re
from datetime import datetime
from multiprocessing import Process, Value, Lock
from mnemonic import Mnemonic

# Funkcija za kreiranje direktorija za pohranu generisanih adresa i ključeva
def create_storage_dir():
    directory = "generated_addresses"
    os.makedirs(directory, exist_ok=True)
    return directory

# Funkcija za Base58Check enkodiranje
def base58check_encode(version_byte, payload):
    versioned_payload = bytes([version_byte]) + payload
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    return base58.b58encode(versioned_payload + checksum)

# Funkcija za provjeru Bitcoin adrese preko regexa
def validate_btc_address(address):
    pattern = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
    return bool(pattern.match(address))

# Funkcija za spremanje generisanih podataka u fajlove
def save_to_file(batch_with_balance, batch_without_balance, electrum_addresses):
    directory = create_storage_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Datoteka za adrese sa balansom
    with open(f"{directory}/generated_with_balance_{timestamp}.txt", 'w') as f:
        for entry in batch_with_balance:
            private_key, address, wif_key, mnemonic_phrase = entry
            f.write(f"Private Key (hex): {private_key}\n")
            f.write(f"Address: {address}\n")
            f.write(f"WIF Key: {wif_key}\n")
            f.write(f"Mnemonic Phrase: {mnemonic_phrase}\n")
            f.write("------\n")

    # Datoteka za adrese bez balansa
    with open(f"{directory}/generated_without_balance_{timestamp}.txt", 'w') as f:
        for entry in batch_without_balance:
            private_key, address, wif_key, mnemonic_phrase = entry
            f.write(f"Private Key (hex): {private_key}\n")
            f.write(f"Address: {address}\n")
            f.write(f"WIF Key: {wif_key}\n")
            f.write(f"Mnemonic Phrase: {mnemonic_phrase}\n")
            f.write("------\n")

    # Datoteka za Electrum uvoz
    with open(f"{directory}/electrum_import_{timestamp}.txt", 'w') as f:
        for address in electrum_addresses:
            f.write(f"{address}\n")

# Funkcija za generisanje mnemonika i seed-a
def generate_mnemonic_and_seed():
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=256)
    seed = mnemo.to_seed(mnemonic_phrase)
    return mnemonic_phrase, seed

# Funkcija za generisanje Bitcoin adrese iz seed-a
def generate_btc_address(seed):
    public_key_hash = hashlib.new("ripemd160", hashlib.sha256(seed).digest()).digest()
    btc_address = base58check_encode(0x00, public_key_hash).decode()
    return btc_address

# Funkcija za provjeru salda na adresi (dummy funkcija, zamijenite pravim API pozivom)
def check_balance(address):
    return secrets.choice([True, False])  # Nasumično vraća True ili False kao test

# Glavna funkcija za generisanje i spremanje adresa
def generate_and_save_addresses(valid_addresses, invalid_addresses, target_valid_addresses, lock, batch_size=100):
    batch_with_balance = []
    batch_without_balance = []
    electrum_addresses = []
    
    while valid_addresses.value < target_valid_addresses:
        mnemonic_phrase, seed = generate_mnemonic_and_seed()
        btc_address = generate_btc_address(seed)
        
        private_key = secrets.token_bytes(32)
        wif_key = base58check_encode(0x80, private_key).decode()

        # Provjeravamo balans adrese
        has_balance = check_balance(btc_address)

        # Spremamo adresu prema statusu balansa
        if validate_btc_address(btc_address):
            with lock:
                valid_addresses.value += 1
            entry = (private_key.hex(), btc_address, wif_key, mnemonic_phrase)
            if has_balance:
                batch_with_balance.append(entry)
            else:
                batch_without_balance.append(entry)
            # Dodavanje adrese u listu za Electrum
            electrum_addresses.append(btc_address)
        else:
            with lock:
                invalid_addresses.value += 1

        # Spremanje nakon što se sakupi batch
        if len(batch_with_balance) >= batch_size or len(batch_without_balance) >= batch_size:
            save_to_file(batch_with_balance, batch_without_balance, electrum_addresses)
            batch_with_balance.clear()
            batch_without_balance.clear()
            electrum_addresses.clear()

        # Prikaz statusa sa brojačima
        print(f"\r Invalid Addresses: {invalid_addresses.value} - Valid Addresses: {valid_addresses.value} - (Status: Generating addresses)", end="\r")

# Main funkcija
def main():
    print("\nWELCOME TO BITRON\n")
    target_valid_addresses = int(input("ENTER NUMBER OF VALID KEYS TO GENERATE:\n\n----------------->> "))

    valid_addresses = Value('i', 0)
    invalid_addresses = Value('i', 0)
    lock = Lock()
    processes = []

    for _ in range(5):  # Start 5 processes for parallel generation
        p = Process(target=generate_and_save_addresses, args=(valid_addresses, invalid_addresses, target_valid_addresses, lock))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    print("\nScript completed address generation.")

if __name__ == "__main__":
    main()
