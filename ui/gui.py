import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
from db.database import init_db
from util.hash_util import hash_password
from util.validation import validate_password_strength, generate_strong_password
from util.encryption import encrypt_password, decrypt_password
from util.otp import generate_otp, send_otp

init_db()

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Password Manager")
        self.root.geometry("450x500")
        self.root.configure(bg="#f0f0f0")
        self.user_id = None
        self.master_password = None

        self.login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def title_label(self, text):
        label = tk.Label(self.root, text=text, font=("Arial", 18, "bold"), bg="#4a7abc", fg="white", pady=10)
        label.pack(fill="x")

    def login_screen(self):
        self.clear_screen()
        self.title_label("🔐 Password Manager Login")

        frame = tk.Frame(self.root, pady=20, bg="#f0f0f0")
        frame.pack()

        ttk.Label(frame, text="Email").pack(pady=5)
        email_entry = ttk.Entry(frame, width=30)
        email_entry.pack()

        ttk.Label(frame, text="Master Password").pack(pady=5)
        password_entry = ttk.Entry(frame, width=30, show="*")
        password_entry.pack()

        def login():
            email = email_entry.get()
            password = password_entry.get()
            hashed = hash_password(password)

            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ? AND master_password = ?", (email, hashed))
            result = cursor.fetchone()
            conn.close()

            if result:
                self.user_id = result[0]
                self.master_password = password
                messagebox.showinfo("Success", "Logged in successfully!")
                self.home_screen()
            else:
                messagebox.showerror("Error", "Invalid email or password.")

        def go_to_register():
            self.register_screen()

        ttk.Button(frame, text="Login", command=login).pack(pady=10)
        ttk.Button(frame, text="Register", command=go_to_register).pack()

    def register_screen(self):
        self.clear_screen()
        self.title_label("📋 Register New Account")

        frame = tk.Frame(self.root, pady=20, bg="#f0f0f0")
        frame.pack()

        ttk.Label(frame, text="Email").pack(pady=5)
        email_entry = ttk.Entry(frame, width=30)
        email_entry.pack()

        ttk.Label(frame, text="Master Password").pack(pady=5)
        password_entry = ttk.Entry(frame, width=30, show="*")
        password_entry.pack()

        ttk.Label(frame, text="Confirm Password").pack(pady=5)
        confirm_entry = ttk.Entry(frame, width=30, show="*")
        confirm_entry.pack()

        def register():
            email = email_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            valid, message = validate_password_strength(password)
            if not valid:
                messagebox.showerror("Error", message)
                return

            hashed_password = hash_password(password)

            try:
                conn = sqlite3.connect("passwords.db")
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (email, master_password) VALUES (?, ?)", (email, hashed_password))
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", "Account created. Please log in.")
                self.login_screen()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Account with this email already exists.")

        ttk.Button(frame, text="Register", command=register).pack(pady=10)
        ttk.Button(frame, text="Back to Login", command=self.login_screen).pack()

    def home_screen(self):
        self.clear_screen()
        self.title_label("🏠 Home")

        frame = tk.Frame(self.root, pady=50, bg="#f0f0f0")
        frame.pack()

        ttk.Button(frame, text="Add New Password", command=self.add_password_screen, width=25).pack(pady=10)
        ttk.Button(frame, text="View Stored Passwords", command=self.view_password_screen, width=25).pack(pady=10)
        ttk.Button(frame, text="Logout", command=self.login_screen, width=25).pack(pady=10)

    def add_password_screen(self):
        self.clear_screen()
        self.title_label("➕ Add Password")

        frame = tk.Frame(self.root, pady=20, bg="#f0f0f0")
        frame.pack()

        ttk.Label(frame, text="Website").pack(pady=5)
        website_entry = ttk.Entry(frame, width=30)
        website_entry.pack()

        ttk.Label(frame, text="Username").pack(pady=5)
        username_entry = ttk.Entry(frame, width=30)
        username_entry.pack()

        ttk.Label(frame, text="Password").pack(pady=5)
        password_entry = ttk.Entry(frame, width=30)
        password_entry.pack()

        def generate_password():
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generate_strong_password())

        def save_password():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()

            encrypted_password = encrypt_password(password, self.master_password)

            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO vault (user_id, website, username, password) VALUES (?, ?, ?, ?)",
                           (self.user_id, website, username, encrypted_password))
            conn.commit()
            conn.close()

            messagebox.showinfo("Success", "Password saved.")
            self.home_screen()

        ttk.Button(frame, text="Generate Strong Password", command=generate_password).pack(pady=10)
        ttk.Button(frame, text="Save Password", command=save_password).pack(pady=10)
        ttk.Button(frame, text="Back", command=self.home_screen).pack(pady=10)

    def view_password_screen(self):
        self.clear_screen()
        self.title_label("🔑 View Passwords (OTP Protected)")

        otp = generate_otp()

        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE id = ?", (self.user_id,))
        user_email = cursor.fetchone()[0]

        send_otp(user_email, otp)

        user_otp = simpledialog.askstring("OTP Verification", "Enter OTP sent to your email:")

        if user_otp != otp:
            messagebox.showerror("Error", "Invalid OTP.")
            self.home_screen()
            return

        cursor.execute("SELECT id, website, username, password FROM vault WHERE user_id = ?", (self.user_id,))
        results = cursor.fetchall()
        conn.close()

        if not results:
            messagebox.showinfo("No passwords", "No passwords stored.")
            self.home_screen()
            return

        for row in results:
            record_id, website, username, encrypted_password = row
            try:
                decrypted_password = decrypt_password(encrypted_password, self.master_password)
            except:
                decrypted_password = "Cannot decrypt"

            frame = tk.Frame(self.root, pady=5)
            frame.pack()

            tk.Label(frame, text=f"Website: {website} | Username: {username} | Password: {decrypted_password}").pack(side="left")
            ttk.Button(frame, text="Edit", command=lambda rid=record_id, w=website, u=username, p=decrypted_password: self.edit_password(rid, w, u, p)).pack(side="right")

        ttk.Button(self.root, text="Back", command=self.home_screen).pack(pady=20)

    def edit_password(self, record_id, website, username, password):
        edit_win = tk.Toplevel(self.root)
        edit_win.title("Edit Password")
        edit_win.geometry("300x300")

        tk.Label(edit_win, text="Website").pack(pady=5)
        website_entry = ttk.Entry(edit_win, width=30)
        website_entry.pack()
        website_entry.insert(0, website)

        tk.Label(edit_win, text="Username").pack(pady=5)
        username_entry = ttk.Entry(edit_win, width=30)
        username_entry.pack()
        username_entry.insert(0, username)

        tk.Label(edit_win, text="Password").pack(pady=5)
        password_entry = ttk.Entry(edit_win, width=30)
        password_entry.pack()
        password_entry.insert(0, password)

        def generate_password():
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generate_strong_password())

        def save_changes():
            new_website = website_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()

            encrypted_password = encrypt_password(new_password, self.master_password)

            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("UPDATE vault SET website = ?, username = ?, password = ? WHERE id = ?",
                           (new_website, new_username, encrypted_password, record_id))
            conn.commit()
            conn.close()

            messagebox.showinfo("Success", "Password updated.")
            edit_win.destroy()
            self.view_password_screen()

        ttk.Button(edit_win, text="Generate Strong Password", command=generate_password).pack(pady=10)
        ttk.Button(edit_win, text="Save Changes", command=save_changes).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
