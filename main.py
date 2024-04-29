from PasswordManager import PasswordManager

def main():
    try:
        PasswordManager.manage_master_password()
    except Exception as e:
        print(f"An error occurred while managing the master password: {e}")
        return

    while True:
        try:
            # Menu
            print("\n1. Add a new password")
            print("2. View existing passwords")
            print("3. Search the password list")
            print("4. Generate a secure password")
            print("5. Exit")
            choice = input("Enter your choice: ")

            # Choice Logic
            if choice == '1':
                site = input("\nEnter website: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                PasswordManager.store_password(site, username, password)
            elif choice == '2':
                print(" ")
                PasswordManager.read_passwords()
            elif choice == '3':
                search_type = input("Search by (1) Website or (2) Username? Enter 1 or 2: ")
                search_query = input("Enter search query: ")
                if search_type == '1':
                    print(" ")
                    PasswordManager.search_passwords(search_query, search_type='website')
                else:
                    print(" ")
                    PasswordManager.search_passwords(search_query, search_type='username')
            elif choice == '4':
                secure_password = PasswordManager.generate_secure_password()
                print("\nOne Secure Password Coming Up: " + secure_password)
            elif choice == '5':
                break
            else:
                print("Invalid choice, try again.")
        except ValueError:
            print("Invalid input. Please enter a valid choice.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
