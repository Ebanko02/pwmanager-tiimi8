import json
import re
import random
import string
import os

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)

SHIFT = 3

def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[^\w\s]', password):
        return False
    return True

# Password generator function (optional)
def generate_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pw = "".join(random.choice(alphabet) for _ in range(length))
        if is_strong_password(pw):
            return pw

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 
def add_password(website=None, username=None, password=None):
    if website is None:
        website = input("Website: ").strip()
    if username is None:
        username = input("Username: ").strip()
    if password is None:
        password = input("Password: ")

    encrypted = caesar_encrypt(password, SHIFT)
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted)

# Function to retrieve a password 
def get_password(website=None):
    if website is None:
        website = input("Website to find: ").strip()

    if website in websites:
        idx = websites.index(website)
        user = usernames[idx]
        pw = caesar_decrypt(encrypted_passwords[idx], SHIFT)

        print(f"Username: {user}")
        print(f"Password: {pw}")

        return user, pw

    print("No entry found for that website.")
    return None, None


# Function to save passwords to a JSON file 
def save_passwords(password_list=None, filename="vault.txt"):
    if password_list is None:
        password_list = []
        for i in range(len(websites)):
            password_list.append({
                "website": websites[i],
                "username": usernames[i],
                "password": encrypted_passwords[i]  # salattu
            })

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(password_list, f)

# Function to load passwords from a JSON file 
def load_passwords(filename="vault.txt"):
    if not os.path.exists(filename):
        return []

    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    websites.clear()
    usernames.clear()
    encrypted_passwords.clear()
    for item in data:
        websites.append(item["website"])
        usernames.append(item["username"])
        encrypted_passwords.append(item["password"])

    return data

  # Main method
def main():
# implement user interface 

  while True:
    print("\nPassword Manager Menu:")
    print("1. Add Password")
    print("2. Get Password")
    print("3. Save Passwords")
    print("4. Load Passwords")
    print("5. Quit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        add_password()
    elif choice == "2":
        get_password()
    elif choice == "3":
        save_passwords()
    elif choice == "4":
        passwords = load_passwords()
        print("Passwords loaded successfully!")
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()
