# app_gui.py
import os
import tkinter as tk
from tkinter import Toplevel
from datetime import datetime
from security_manager import verify_user

from tkinter import Label, Entry, Button, Listbox, Scrollbar, messagebox, simpledialog
import logging

# Importing local modules
from security_manager import (
    save_user, delete_user, get_user_details, get_all_user_details,
    verify_password, verify_facial_recognition
)
from camera_capture import capture_image
from config import current_config

IMAGE_SAVE_PATH = current_config.IMAGE_SAVE_PATH


def setup_logging():
    logs_directory = '__logs'
    os.makedirs(logs_directory, exist_ok=True)  # Ensure the directory exists
    # Create a filename with the current timestamp in the specified format
    log_filename = datetime.now().strftime('%H-%M-%S %d %b %Y') + '.log'
    log_filepath = os.path.join(logs_directory, log_filename)

    # Set up logging to write to the file with the specified filename
    logging.basicConfig(filename=log_filepath, filemode='w', level=logging.ERROR,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%H:%M:%S %d %b %Y')

    # Add a stream handler to also print errors to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%H:%M:%S %d %b %Y')
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

class AppGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Facial Recognition System")
        self.geometry("800x500")
        setup_logging()
        self.create_widgets()
        self.update_user_list()

    def create_widgets(self):
        """Creates GUI components and organizes them."""
        # Username and Password Entries
        entry_frame = tk.Frame(self)
        entry_frame.pack(pady=10)

        Label(entry_frame, text="Username:").pack(side=tk.LEFT)
        self.username_entry = Entry(entry_frame, width=20)
        self.username_entry.pack(side=tk.LEFT, padx=5)

        Label(entry_frame, text="Password:").pack(side=tk.LEFT)
        self.password_entry = Entry(entry_frame, show="*", width=20)
        self.password_entry.pack(side=tk.LEFT, padx=5)

        # Buttons
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        Button(button_frame, text="Login User", command=self.login_user).pack(side=tk.LEFT, padx=5)
        Button(button_frame, text="Add User", command=self.add_user).pack(side=tk.LEFT, padx=5)
        Button(button_frame, text="Delete User", command=self.delete_user_prompt).pack(side=tk.LEFT, padx=5)
        Button(button_frame, text="Show All Users", command=self.update_user_list).pack(side=tk.LEFT, padx=5)

        # Output Listbox
        self.output_listbox = Listbox(self, width=80, height=10)
        self.output_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        scrollbar = Scrollbar(self.output_listbox, orient="vertical")
        scrollbar.config(command=self.output_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_listbox.config(yscrollcommand=scrollbar.set)

        # CLI Input
        Label(self, text="Enter Command:").pack()
        self.command_entry = Entry(self)
        self.command_entry.pack(fill=tk.X, padx=10, pady=10)  # Make CLI input wider
        self.output_listbox.bind("<Double-1>", self.login_user_by_click)  # Add this line

    def login_user_by_click(self, event):
        """Logs in the user selected from the listbox by double-clicking."""
        selection = self.output_listbox.curselection()
        if selection:
            username = self.output_listbox.get(selection[0])
            password = simpledialog.askstring("Password Input", "Enter your password:", show='*')
            if password:
                input_image_path = capture_image("login_attempt.jpg")
                if input_image_path:
                    try:
                        success, message = verify_user(username, password, input_image_path)
                        messagebox.showinfo("Login Attempt", message)
                    except Exception as e:
                        logging.error(f"Verification failed: {e}")
                        messagebox.showerror("Login Error", "Verification process failed.")
                else:
                    messagebox.showerror("Login Error", "Failed to capture image.")
            else:
                messagebox.showwarning("Login Cancelled", "No password entered.")

    def open_output_window(self):
        if not self.output_window or not self.output_window.winfo_exists():
            self.output_window = Toplevel(self)
            self.output_window.title("Output Window")
            self.output_window.geometry("400x300")
            self.output_listbox = Listbox(self.output_window, width=50, height=15)
            self.output_listbox.pack(padx=10, pady=10)

    def update_user_list(self):
        self.output_listbox.delete(0, tk.END)
        user_details = get_all_user_details()
        for username, details in user_details.items():
            self.output_listbox.insert(tk.END,
                                       f"{username} - {details['password_hash'][:5]}...{details['password_hash'][-5:]}")

    def add_user(self):
        """ Adds a new user """
        username = simpledialog.askstring("Username", "Enter a unique username:")
        if username:
            # Capture an image and save it
            image_filename = f"{username}.jpg"
            capture_image(image_filename)
            image_path = os.path.join(IMAGE_SAVE_PATH, image_filename)
            password = simpledialog.askstring("Password", "Enter your password:", show="*")
            success, message = save_user(username, image_path, password)
            messagebox.showinfo("Result", message)
            if success:
                self.update_user_list()

    def execute_login(self, username, password):
        """Executes user login by checking username and password, logs errors if occurred."""
        try:
            if username and password:
                user_details = get_user_details(username)
                if not user_details:
                    self.output_listbox.insert(tk.END, "Login Failed - User does not exist.")
                    logging.error("Login failed: No such user exists - %s", username)
                    return

                if self.verify_login(username, password):
                    self.output_listbox.insert(tk.END, "Login Successful - Account verified.")
                else:
                    self.output_listbox.insert(tk.END, "Login Failed - Incorrect credentials.")
                    logging.warning("Failed login attempt for user - %s", username)
            else:
                self.output_listbox.insert(tk.END, "Login Failed - Username and password must be provided.")
                logging.error("Login failed: Username and/or password not provided.")
        except Exception as e:
            self.output_listbox.insert(tk.END, "Login Failed - An error occurred.")
            logging.error("Exception during login for user %s: %s", username, str(e))

    def delete_user_prompt(self):
        """ Deletes a user after confirmation """
        self.execute_delete_user(self.username_entry.get())

    def parse_command(self):
        """ Parses and executes commands entered through the CLI """
        command = self.command_entry.get().strip().split()
        if not command:
            messagebox.showinfo("Error", "No command entered")
            return
        self.command_entry.delete(0, tk.END)

        cmd, *args = command
        cmd = cmd.lower()
        if cmd == "login" and len(args) == 2:
            self.execute_login(*args)
        elif cmd == "add" and len(args) == 2:
            self.execute_add_user(*args)
        elif cmd == "delete" and len(args) == 1:
            self.execute_delete_user(*args[0])
        elif cmd == "show":
            self.update_user_list()
        else:
            messagebox.showinfo("Error", "Unknown command or incorrect parameters")

    def login_user(self):
        """ Handles user login with facial recognition and password verification """
        self.execute_login(self.username_entry.get(), self.password_entry.get())

    def execute_add_user(self, username, password):
        if username and password:
            new_image_path = capture_image(f"{username}.jpg")
            if new_image_path:
                success, message = save_user(username, new_image_path, password)
                self.output_listbox.insert(tk.END, f"Add User - {message}")
                if success:
                    self.update_user_list()
            else:
                self.output_listbox.insert(tk.END, "Error - Failed to capture image.")

    def verify_login(self, username, password):
        """Verifies user's identity by checking password and facial recognition"""
        user_details = get_user_details(username)
        if not user_details:
            messagebox.showinfo("Login Failed", "User not found.")
            return False

        new_image_path = capture_image("login_attempt.jpg")
        if not new_image_path:
            messagebox.showinfo("Login Error", "Failed to capture image.")
            return False

        face_match = verify_facial_recognition(user_details['image_path'], new_image_path)
        password_match = verify_password(user_details['password_hash'], user_details['salt'], password)

        if face_match and password_match:
            messagebox.showinfo("Login Successful", "Account verified.")
            return True
        else:
            errors = []
            if not face_match:
                errors.append("face verification failed")
            if not password_match:
                errors.append("password verification failed")
            messagebox.showinfo("Login Failed", " and ".join(errors).capitalize() + ".")
            return False

    def execute_delete_user(self, username):
        """Deletes a user after verifying password and facial recognition"""
        if not username:
            self.output_listbox.insert(tk.END, "Deletion Failed - No username provided")
            return

        # Prompt for password
        password = simpledialog.askstring("Password Verification", f"Enter password for {username}:", show="*")
        if not password:
            self.output_listbox.insert(tk.END, "Deletion Failed - No password provided")
            return

        # Retrieve user details for verification
        user_details = get_user_details(username)
        if not user_details:
            self.output_listbox.insert(tk.END, "Deletion Failed - User doesn't exist")
            return

        # Verify password
        password_match = verify_password(user_details['password_hash'], user_details['salt'], password)
        if not password_match:
            self.output_listbox.insert(tk.END, "Deletion Failed - Incorrect password")
            return

        # Capture a new image for facial recognition verification
        new_image_path = capture_image("delete_attempt.jpg")
        if not new_image_path:
            self.output_listbox.insert(tk.END, "Deletion Failed - Unable to capture image")
            return

        # Verify facial recognition
        face_match = verify_facial_recognition(user_details['image_path'], new_image_path)
        if not face_match:
            self.output_listbox.insert(tk.END, "Deletion Failed - Facial recognition did not match")
            return

        # If all checks pass, delete the user
        success, message = delete_user(username)
        if success:
            self.output_listbox.insert(tk.END, f"User {username} deleted successfully")
            self.update_user_list()  # Refresh the user list
        else:
            self.output_listbox.insert(tk.END, f"Deletion Failed - {message}")

    def delete_user(self):
        username = simpledialog.askstring("Delete User", "Enter username to delete:")
        if not username:
            self.output_listbox.insert(tk.END, "Deletion Failed - No username provided")
            return

        if not self.verify_user_details(username):
            return

        new_image_path = capture_image("delete_attempt.jpg")
        if not new_image_path:
            self.output_listbox.insert(tk.END, "Deletion Failed - Unable to capture image")
            return

        if not self.verify_facial_recognition_for_user(username, new_image_path):
            return

        if self.execute_user_deletion(username):
            self.output_listbox.insert(tk.END, f"User {username} deleted successfully")
            self.update_user_list()  # Refresh the user list
        else:
            self.output_listbox.insert(tk.END, "Deletion Failed - Error during deletion process")

    def add_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            self.output_listbox.insert(tk.END, "Addition Failed - Username or password cannot be empty")
            return

        if self.execute_add_user(username, password):
            self.output_listbox.insert(tk.END, f"User {username} added successfully")
            self.update_user_list()  # Refresh the user list
        else:
            self.output_listbox.insert(tk.END, "Addition Failed - Error during user creation")


if __name__ == "__main__":
    setup_logging()
    app = AppGUI()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        print("Application interrupted. Closing program.")
        app.destroy()
