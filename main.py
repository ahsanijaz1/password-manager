from db.database import init_db
from util.encryption import encrypt_password, decrypt_password, hash_password
from util.validation import validate_password_strength

import sqlite3

def register_master_account():
    email = input("Enter your email: ")
    password = input("Create a master password: ")
    confirm_password = input("Confirm your master password: ")

    if password != confirm_password:
        print("Passwords do not match.")
        return

    valid, message = validate_password_strength(password)
    if not valid:
        print(f"Password error: {message}")
        return

    hashed_password = hash_password(password)

    try:
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, master_password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        conn.close()
        print("Master account created successfully!")
    except sqlite3.IntegrityError:
        print("An account with this email already exists.")

def login():
    email = input("Enter your email: ")
    password = input("Enter your master password: ")
    hashed = hash_password(password)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND master_password = ?", (email, hashed))
    result = cursor.fetchone()
    conn.close()

    if result:
        print("Login successful! Welcome.")
        return result[0]  # return user_id
    else:
        print("Invalid email or password.")
        return None
    

#Storing passwords in a vault
def store_password(user_id):
    website = input("Enter website name: ")
    username = input("Enter username: ")
    password = input("Enter password for the site: ")
    master_password = input("Enter your master password again to encrypt this password: ")

    encrypted_password = encrypt_password(password, master_password)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO vault (user_id, website, username, password) VALUES (?, ?, ?, ?)",
                   (user_id, website, username, encrypted_password))
    conn.commit()
    conn.close()

    print("Password stored successfully!")




#Retrieving passwords from the vault
def view_passwords(user_id):
    master_password = input("Enter your master password to view passwords: ")

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT website, username, password FROM vault WHERE user_id = ?", (user_id,))
    results = cursor.fetchall()
    conn.close()

    if results:
        for row in results:
            website, username, encrypted_password = row
            try:
                decrypted_password = decrypt_password(encrypted_password, master_password)
                print(f"Website: {website}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*20}")
            except Exception as e:
                print(f"Website: {website}\nUsername: {username}\nPassword: Cannot decrypt (Wrong master password)\n{'-'*20}")
    else:
        print("No passwords stored.")



if __name__ == "__main__":
    init_db()

    print("1. Register")
    print("2. Login")
    choice = input("Choose an option (1 or 2): ")

    if choice == "1":
        register_master_account()
    elif choice == "2":
        user_id = login()
    if user_id:
        while True:
            print("\n1. Store a new password")
            print("2. View stored passwords")
            print("3. Exit")
            option = input("Choose an option: ")

            if option == "1":
                store_password(user_id)
            elif option == "2":
                view_passwords(user_id)
            elif option == "3":
                break
            else:
                print("Invalid option. Try again.")





