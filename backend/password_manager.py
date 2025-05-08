import sqlite3
from backend.util.encryption import encrypt_password
from backend.util.hash_util import hash_password


def save_password(user_id, website, username, password, master_password):
    encrypted_password = encrypt_password(password, master_password)
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO vault (user_id, website, username, password) VALUES (?, ?, ?, ?)",
                   (user_id, website, username, encrypted_password))
    conn.commit()
    conn.close()

def get_passwords(user_id, master_password):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, website, username, password FROM vault WHERE user_id = ?", (user_id,))
    results = cursor.fetchall()
    conn.close()

    return results

def delete_password(record_id):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

def edit_password(record_id, website, username, password, master_password):
    encrypted_password = encrypt_password(password, master_password)
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE vault SET website = ?, username = ?, password = ? WHERE id = ?",
                   (website, username, encrypted_password, record_id))
    conn.commit()
    conn.close()
