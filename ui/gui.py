import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
from db.database import init_db
from backend.util.hash_util import hash_password
from backend.util.validation import validate_password_strength, generate_strong_password
from backend.util.otp import generate_otp, send_otp
from backend.util.encryption import decrypt_password

from backend import password_manager

init_db()

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("500x550")
        self.root.configure(bg="#e8f0fe")

        # Styles
        style = ttk.Style()
        style.configure("Custom.TButton", font=("Segoe UI", 11), padding=6)
        style.configure("Custom.TLabel", font=("Segoe UI", 11), background="#e8f0fe")
        style.configure("Custom.TEntry", font=("Segoe UI", 11))
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), background="#4a7abc", foreground="white", padding=15)

        self.user_id = None
        self.master_password = None

        self.login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def title_label(self, text):
        ttk.Label(self.root, text=text, style="Title.TLabel").pack(fill="x")

    def login_screen(self):
        self.clear_screen()
        self.title_label("Password Manager Login")

        frame = tk.Frame(self.root, pady=30, bg="#e8f0fe")
        frame.pack()

        ttk.Label(frame, text="Email", style="Custom.TLabel").pack(pady=5)
        email_entry = ttk.Entry(frame, width=35, style="Custom.TEntry")
        email_entry.pack()

        ttk.Label(frame, text="Master Password", style="Custom.TLabel").pack(pady=5)
        password_entry = ttk.Entry(frame, width=35, show="*", style="Custom.TEntry")
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

        ttk.Button(frame, text="Login", command=login, style="Custom.TButton").pack(pady=10)
        ttk.Button(frame, text="Register", command=go_to_register, style="Custom.TButton").pack()

    def register_screen(self):
        self.clear_screen()
        self.title_label("Register New Account")

        frame = tk.Frame(self.root, pady=30, bg="#e8f0fe")
        frame.pack()

        ttk.Label(frame, text="Email", style="Custom.TLabel").pack(pady=5)
        email_entry = ttk.Entry(frame, width=35, style="Custom.TEntry")
        email_entry.pack()

        ttk.Label(frame, text="Master Password", style="Custom.TLabel").pack(pady=5)
        password_entry = ttk.Entry(frame, width=35, show="*", style="Custom.TEntry")
        password_entry.pack()

        ttk.Label(frame, text="Confirm Password", style="Custom.TLabel").pack(pady=5)
        confirm_entry = ttk.Entry(frame, width=35, show="*", style="Custom.TEntry")
        confirm_entry.pack()

        def register():
            email = email_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()

            if not email or not password or not confirm:
                messagebox.showerror("Error", "All fields are required.")
                return

            if "@" not in email or "." not in email:
                messagebox.showerror("Error", "Enter a valid email address.")
                return

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

        ttk.Button(frame, text="Register", command=register, style="Custom.TButton").pack(pady=10)
        ttk.Button(frame, text="Back to Login", command=self.login_screen, style="Custom.TButton").pack()

    def home_screen(self):
        self.clear_screen()
        self.title_label("Home")

        frame = tk.Frame(self.root, pady=40, bg="#e8f0fe")
        frame.pack()

        ttk.Button(frame, text="Add New Password", command=self.add_password_screen, width=30, style="Custom.TButton").pack(pady=10)
        ttk.Button(frame, text="View Stored Passwords", command=self.view_password_screen, width=30, style="Custom.TButton").pack(pady=10)
        ttk.Button(frame, text="Logout", command=self.login_screen, width=30, style="Custom.TButton").pack(pady=10)
    def add_password_screen(self):
        self.clear_screen()
        self.title_label("Add Password")

        frame = tk.Frame(self.root, pady=20, bg="#e8f0fe")
        frame.pack()

        ttk.Label(frame, text="Website", style="Custom.TLabel").pack(pady=5)
        website_entry = ttk.Entry(frame, width=35, style="Custom.TEntry")
        website_entry.pack()

        ttk.Label(frame, text="Username", style="Custom.TLabel").pack(pady=5)
        username_entry = ttk.Entry(frame, width=35, style="Custom.TEntry")
        username_entry.pack()

        ttk.Label(frame, text="Password", style="Custom.TLabel").pack(pady=5)
        password_entry = ttk.Entry(frame, width=35, style="Custom.TEntry")
        password_entry.pack()

        def generate_password():
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generate_strong_password())

        def save_password():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()

            if not website or not username or not password:
                messagebox.showerror("Error", "All fields are required.")
                return

            password_manager.save_password(self.user_id, website, username, password, self.master_password)
            messagebox.showinfo("Success", "Password saved.")
            self.home_screen()

        ttk.Button(frame, text="Generate Strong Password", command=generate_password, style="Custom.TButton").pack(pady=10)
        ttk.Button(frame, text="Save Password", command=save_password, style="Custom.TButton").pack(pady=10)
        ttk.Button(frame, text="Back", command=self.home_screen, style="Custom.TButton").pack(pady=10)

    def view_password_screen(self):
            self.clear_screen()
            self.title_label("View Passwords (OTP Protected)")

            otp = generate_otp()

            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE id = ?", (self.user_id,))
            user_email = cursor.fetchone()[0]
            conn.close()

            send_otp(user_email, otp)

            user_otp = simpledialog.askstring("OTP Verification", "Enter OTP sent to your email:")

            if user_otp != otp:
                messagebox.showerror("Error", "Invalid OTP.")
                self.home_screen()
                return

            passwords = password_manager.get_passwords(self.user_id, self.master_password)

            if not passwords:
                messagebox.showinfo("No passwords", "No passwords stored.")
                self.home_screen()
                return

            for record_id, website, username, password in passwords:
                frame = tk.Frame(self.root, pady=5, bg="#e8f0fe")
                frame.pack()

                # Show password as **********
                masked_password = "**********" if password != "Cannot decrypt" else "Cannot decrypt"
                ttk.Label(frame, text=f"{website} | {username} | {masked_password}", style="Custom.TLabel").pack(side="left", padx=5)

                # View Button (enter master password again)
                ttk.Button(frame, text="View", command=lambda rid=record_id, enc_pw=password: self.view_single_password(rid, enc_pw), style="Custom.TButton").pack(side="left", padx=5)

                # Edit Button
                ttk.Button(frame, text="Edit", command=lambda rid=record_id, w=website, u=username, p=password: self.edit_password(rid, w, u, p), style="Custom.TButton").pack(side="left", padx=5)

                # Delete Button
                ttk.Button(frame, text="Delete", command=lambda rid=record_id: self.delete_password(rid), style="Custom.TButton").pack(side="left", padx=5)

            ttk.Button(self.root, text="Back", command=self.home_screen, style="Custom.TButton").pack(pady=20)


    def copy_to_clipboard(self, text):
        if text == "Cannot decrypt":
            messagebox.showerror("Error", "Password cannot be copied.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def delete_password(self, record_id):
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?")
        if confirm:
            password_manager.delete_password(record_id)
            messagebox.showinfo("Deleted", "Password has been deleted.")
            self.view_password_screen()

    def edit_password(self, record_id, website, username, password):
        edit_win = tk.Toplevel(self.root)
        edit_win.title("Edit Password")
        edit_win.geometry("300x300")
        edit_win.configure(bg="#e8f0fe")

        ttk.Label(edit_win, text="Website", style="Custom.TLabel").pack(pady=5)
        website_entry = ttk.Entry(edit_win, width=30, style="Custom.TEntry")
        website_entry.pack()
        website_entry.insert(0, website)

        ttk.Label(edit_win, text="Username", style="Custom.TLabel").pack(pady=5)
        username_entry = ttk.Entry(edit_win, width=30, style="Custom.TEntry")
        username_entry.pack()
        username_entry.insert(0, username)

        ttk.Label(edit_win, text="Password", style="Custom.TLabel").pack(pady=5)
        password_entry = ttk.Entry(edit_win, width=30, style="Custom.TEntry")
        password_entry.pack()
        password_entry.insert(0, password)

        def generate_password():
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generate_strong_password())

        def save_changes():
            new_website = website_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()

            if not new_website or not new_username or not new_password:
                messagebox.showerror("Error", "All fields are required.")
                return

            password_manager.edit_password(record_id, new_website, new_username, new_password, self.master_password)
            messagebox.showinfo("Success", "Password updated.")
            edit_win.destroy()
            self.view_password_screen()

        ttk.Button(edit_win, text="Generate Strong Password", command=generate_password, style="Custom.TButton").pack(pady=10)
        ttk.Button(edit_win, text="Save Changes", command=save_changes, style="Custom.TButton").pack(pady=10)

    def view_single_password(self, record_id, encrypted_password):
        # Ask master password again
        master_password_input = simpledialog.askstring("Master Password", "Enter your master password:")

        if master_password_input != self.master_password:
            messagebox.showerror("Error", "Wrong master password.")
            return

        # Decrypt password
        try:
            decrypted_password = encrypted_password if encrypted_password == "Cannot decrypt" else \
            decrypt_password(encrypted_password, self.master_password)
        except:
                decrypted_password = "Cannot decrypt"

            # Show password in new window
        view_win = tk.Toplevel(self.root)
        view_win.title("View Password")
        view_win.geometry("300x200")
        view_win.configure(bg="#e8f0fe")

        ttk.Label(view_win, text=f"Password: {decrypted_password}", style="Custom.TLabel").pack(pady=20)

        def copy_password():
            if decrypted_password == "Cannot decrypt":
                messagebox.showerror("Error", "Cannot copy this password.")
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted_password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        ttk.Button(view_win, text="Copy Password", command=copy_password, style="Custom.TButton").pack(pady=10)
        ttk.Button(view_win, text="Close", command=view_win.destroy, style="Custom.TButton").pack(pady=10)





if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
