import os
import base64
import random
import string

class PasswordManager:
    def rot_cipher(text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                start = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - start + shift) % 26 + start)
            else:
                result += char
        return result

    def base64_encode(text):
        return base64.b64encode(text.encode()).decode()

    def base64_decode(encoded_text):
        return base64.b64decode(encoded_text).decode()

    def vigenere_cipher(text, key, mode='encrypt'):
        result = ""
        key_length = len(key)
        key_index = 0
        for char in text:
            shift = ord(key[key_index]) - ord('a')
            if mode == 'encrypt':
                result += PasswordManager.rot_cipher(char, shift)
            elif mode == 'decrypt':
                result += PasswordManager.rot_cipher(char, -shift)
            key_index = (key_index + 1) % key_length
        return result

    def manage_master_password():
        key = "ThisIsASuperSecretKey"
        if not os.path.exists('passwords.enc'):
            master_password = input("Password file not detected, enter a master password to start: ")
            PasswordManager.store_password("master", "password", master_password)
            print("Master password set.")
        else:
            attempt = input("Enter the master password to access the menu: ")
            if PasswordManager.verify_master_password(attempt):
                print("Password verified successfully. Accessing the menu.")
            else:
                print("Incorrect master password. Exiting.")
                exit()

    def store_password(site, username, password):
        key = "ThisIsASuperSecretKey"
        encrypted_data = []
        for data in [site, username, password]:
            rot_encoded = PasswordManager.rot_cipher(data, 16)
            base64_encoded = PasswordManager.base64_encode(rot_encoded)
            encrypted = PasswordManager.vigenere_cipher(base64_encoded, key)
            encrypted_data.append(encrypted)
        
        with open('passwords.enc', 'a') as file:
            file.write(','.join(encrypted_data) + '\n')
        print("Data encrypted and stored successfully.")

    def verify_master_password(input_password):
        with open('passwords.enc', 'r') as file:
            encrypted_master_password = file.readline().split(',')[2]
        return PasswordManager.decode_password(encrypted_master_password) == input_password

    def decode_password(encrypted_password):
        key = "ThisIsASuperSecretKey"
        decrypted_base64 = PasswordManager.vigenere_cipher(encrypted_password, key, mode='decrypt')
        decoded_rot = PasswordManager.base64_decode(decrypted_base64)
        original_password = PasswordManager.rot_cipher(decoded_rot, -16)
        return original_password

    def read_passwords():
        key = "ThisIsASuperSecretKey"
        if os.path.exists('passwords.enc'):
            with open('passwords.enc', 'r') as file:
                lines = file.readlines()
            for index, line in enumerate(lines):
                encrypted_site, encrypted_username, encrypted_password = line.strip().split(',')
                site = PasswordManager.decode_password(encrypted_site)
                username = PasswordManager.decode_password(encrypted_username)
                password = PasswordManager.decode_password(encrypted_password)
                if index == 0:
                    print(f"Master Password: {password}")
                else:
                    print(f"Website: {site}, Username: {username}, Password: {password}")
        else:
            print("No passwords stored.")

    def generate_secure_password():
        password_characters = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = [
                random.choice(string.ascii_uppercase),
                random.choice(string.ascii_lowercase),
                random.choice(string.digits),
                random.choice(string.punctuation)
            ]
            password += [random.choice(password_characters) for _ in range(18)]
            random.shuffle(password)
            password = ''.join(password)
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password)):
                return password
    
    def search_passwords(query, search_type='website'):
        # Set cipher key
        key = "ThisIsASuperSecretKey"

        # Open file
        with open('passwords.enc', 'r') as file:
            lines = file.readlines()
        found = False
        for line in lines:
            encrypted_site, encrypted_username, encrypted_password = line.strip().split(',')
            site = PasswordManager.decode_password(encrypted_site)
            username = PasswordManager.decode_password(encrypted_username)
            password = PasswordManager.decode_password(encrypted_password)
            # Check if query is in site or username based on search_type
            if (search_type == 'website' and query.lower() in site.lower()) or \
            (search_type == 'username' and query.lower() in username.lower()):
                print(f"Website: {site}, Username: {username}, Password: {password}")
                found = True
        if not found:
            print("No matching entries found.")
