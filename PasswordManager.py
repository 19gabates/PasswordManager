import os
import base64
import random
import string

class PasswordManager:
    # Global key used for encryption/decryption
    KEY = "ThisIsASuperSecretKey"

    def rot_cipher(text, shift):
        # Implements a simple rotation (Caesar) cipher
        result = ""
        for char in text:
            if char.isalpha():
                start = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - start + shift) % 26 + start)
            else:
                result += char
        return result

    def base64_encode(text):
        # Encodes text to base64
        return base64.b64encode(text.encode()).decode()

    def base64_decode(encoded_text):
        # Decodes text from base64
        return base64.b64decode(encoded_text).decode()

    def vigenere_cipher(text, key, mode='encrypt'):
        # Implements a Vigenere cipher for encryption or decryption
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
        # Handles the creation or verification of the master password
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
        # Encrypts and stores password information
        encrypted_data = []
        for data in [site, username, password]:
            rot_encoded = PasswordManager.rot_cipher(data, 16)
            base64_encoded = PasswordManager.base64_encode(rot_encoded)
            encrypted = PasswordManager.vigenere_cipher(base64_encoded, PasswordManager.KEY)
            encrypted_data.append(encrypted)
        
        with open('passwords.enc', 'a') as file:
            file.write(','.join(encrypted_data) + '\n')
        print("Data encrypted and stored successfully.")

    def verify_master_password(input_password):
        # Verifies the master password against the stored version
        with open('passwords.enc', 'r') as file:
            encrypted_master_password = file.readline().split(',')[2]
        return PasswordManager.decode_password(encrypted_master_password) == input_password

    def decode_password(encrypted_password):
        # Decrypts an encrypted password
        decrypted_base64 = PasswordManager.vigenere_cipher(encrypted_password, PasswordManager.KEY, mode='decrypt')
        decoded_rot = PasswordManager.base64_decode(decrypted_base64)
        original_password = PasswordManager.rot_cipher(decoded_rot, -16)
        return original_password

    def read_passwords():
        # Reads and displays all stored passwords
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
        # Generates a secure, random password
        password_characters = string.ascii_letters + string.digits + string.punctuation
        while True:
            # Create initial mandatory set of characters

            # Lambda to choose a random character from a given category
            get_char = lambda category: random.choice(category)  
            password = [get_char(string.ascii_uppercase), get_char(string.ascii_lowercase), 
                        get_char(string.digits), get_char(string.punctuation)]
            
            # Extend with additional characters and shuffle
            password += [random.choice(password_characters) for _ in range(16)]
            random.shuffle(password)
            
            # Convert list to string
            password = ''.join(password)
            
            # Check for each character type presence
            check_char = lambda condition: any(condition(c) for c in password)  # Lambda to check conditions
            if (check_char(str.islower) and
                check_char(str.isupper) and
                check_char(str.isdigit) and
                check_char(lambda c: c in string.punctuation)):
                return password

    
    def search_passwords(query, search_type='website'):
        # Searches stored passwords by website or username
        try:
            with open('passwords.enc', 'r') as file:
                lines = file.readlines()
        except FileNotFoundError:
            print("Password file not found. Please ensure the file exists.")
            return
        except IOError:
            print("An error occurred while reading the file.")
            return

        found = False
        for line in lines:
            try:
                encrypted_site, encrypted_username, encrypted_password = line.strip().split(',')
                site = PasswordManager.decode_password(encrypted_site)
                username = PasswordManager.decode_password(encrypted_username)
                password = PasswordManager.decode_password(encrypted_password)
                if (search_type == 'website' and query.lower() in site.lower()) or (search_type == 'username' and query.lower() in username.lower()):
                    print(f"Website: {site}, Username: {username}, Password: {password}")
                    found = True
            except Exception as e:
                print(f"An error occurred while processing the passwords: {e}")

        if not found:
            print("No matching entries found.")

