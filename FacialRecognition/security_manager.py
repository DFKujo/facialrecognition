# security_manager.py
import sqlite3
import hashlib
import face_recognition
import os
import binascii
import logging
from config import current_config

DATABASE_PATH = current_config.DATABASE_PATH

logging.basicConfig(level=logging.INFO)


def create_connection():
    """
    Creates and returns a connection to the SQLite database specified in the configuration.
    Returns:
    sqlite3.Connection: A connection to the database.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        return conn
    except sqlite3.Error as e:
        logging.error(f"Failed to create connection to database: {e}")
        return None


def setup_database():
    """
    Sets up the user database table if it does not already exist.
    """
    with create_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        image_path TEXT NOT NULL,
                        password_hash BLOB NOT NULL,
                        salt BLOB NOT NULL
                    )
                """)
                conn.commit()
            except sqlite3.Error as e:
                logging.error(f"Error setting up database: {e}")


def hash_password(password):
    """
    Hashes a password with a generated salt using PBKDF2 and SHA-256.
    Args:
    password (str): The password to hash.
    Returns:
    tuple: A tuple containing the hashed password and the salt used.
    """
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pwdhash, salt


def save_user(username, image_path, password):
    """
    Saves a new user to the database with hashed password and salt.
    Args:
    username (str): The user's username.
    image_path (str): Path to the user's image.
    password (str): The user's password.
    Returns:
    tuple: A tuple containing a boolean for success and a message.
    """

    pwdhash, salt = hash_password(password)
    try:
        with create_connection() as conn:
            if conn is None:
                return False, "Database connection failed."
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, image_path, password_hash, salt) VALUES (?, ?, ?, ?)",
                           (username, image_path, pwdhash, salt))
            logging.info("Attempting to commit the new user to the database.")
            conn.commit()
            logging.info("User committed successfully.")
            return True, "User saved successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    except Exception as e:
        logging.error(f"Error saving user: {e}")
        return False, "Error occurred while saving user."


def verify_user(username, input_password, input_image_path):
    """Verifies if the provided username, password, and face match those stored in the database."""
    try:
        conn = create_connection()
        if conn is None:
            return False, "Login Failed - Database Connection Error"

        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt, image_path FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user is None:
            return False, "Login Failed - User Doesn't Exist"

        stored_hash, stored_salt, stored_image_path = user

        # Verify password
        input_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode(), stored_salt, 100000)
        if input_hash != stored_hash:
            return False, "Login Failed - Incorrect Password"

        # Verify facial recognition
        face_match = verify_facial_recognition(stored_image_path, input_image_path)
        if not face_match:
            return False, "Login Failed - Facial Recognition Failed"

        return True, "Login Successful"

    except Exception as e:
        logging.error(f"Error during user verification: {str(e)}")
        return False, "Login Failed - Internal Error"

    finally:
        if conn:
            conn.close()
# def verify_user(username, input_password, input_image_path):
#     """Verifies if the provided username, password, and face match those stored in the database.
#     Args:
#         username (str): The user's username.
#         input_password (str): The password provided by the user for verification.
#         input_image_path (str): The path to the image captured during the login attempt for facial recognition.
#     Returns:
#         bool, str: True and a success message if the credentials are correct, False and an error message otherwise.
#     """
#     conn = create_connection()
#     if conn is not None:
#         cursor = conn.cursor()
#         cursor.execute("SELECT password_hash, salt, image_path FROM users WHERE username = ?", (username,))
#         user = cursor.fetchone()
#         conn.close()
#         if user is None:
#             return False, "Login Failed - User Doesn't Exist"
#         stored_hash, stored_salt, stored_image_path = user
#
#         # Verify password
#         input_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode(), stored_salt, 100000)
#         if input_hash != stored_hash:
#             return False, "Login Failed - Incorrect Password"
#
#         # Verify facial recognition
#         face_match = verify_facial_recognition(stored_image_path, input_image_path)
#         if not face_match:
#             return False, "Login Failed - Facial Recognition Failed"
#
#         return True, "Login Successful"
#     else:
#         return False, "Login Failed - Database Connection Error"


def get_all_user_details():
    """
    Retrieves details for all users from the database.
    Returns:
    dict: A dictionary of usernames and their respective details.
    """
    conn = create_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username, image_path, password_hash, salt FROM users")
            users = {row[0]: {'image_path': row[1], 'password_hash': row[2], 'salt': row[3]} for row in
                     cursor.fetchall()}
            return users
        except sqlite3.Error as e:
            print(f"Error fetching user details: {e}")
            return {}
        finally:
            conn.close()
    return {}


def get_user_details(username):
    """
    Retrieves user details from the database.
    Args:
    username (str): The username to look up.
    Returns:
    dict: A dictionary containing the user's image path, password hash, and salt if found; None otherwise.
    """
    conn = create_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT image_path, password_hash, salt FROM users WHERE username = ?", (username,))
            user_details = cursor.fetchone()
            if user_details:
                return {'image_path': user_details[0], 'password_hash': user_details[1], 'salt': user_details[2]}
            else:
                return None
        except sqlite3.Error as e:
            print(f"Error fetching user details for {username}: {e}")
            return None
        finally:
            conn.close()
    return None


def delete_user(username):
    """
    Deletes a user from the database based on username.
    Args:
    username (str): The username of the user to delete.
    Returns:
    tuple: A tuple containing a boolean for success and a message.
    """
    conn = create_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            if cursor.rowcount == 0:
                return False, f"No user found with username '{username}'."
            conn.commit()
            return True, "User deleted successfully."
        except sqlite3.Error as e:
            print(f"Error deleting user: {e}")
            return False, f"Error deleting user: {e}"
        finally:
            conn.close()
    return False, "Database connection error"


def verify_password(stored_hash, stored_salt, input_password):
    """
    Verifies a user's password.
    Args:
        stored_hash (bytes): The stored password hash.
        stored_salt (bytes): The stored salt used for hashing the password.
        input_password (str): The password provided by the user for verification.
    Returns:
        bool: True if the password is correct, False otherwise.
    """
    input_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode(), stored_salt, 100000)
    return input_hash == stored_hash

def save_user(username, image_path, password):
    """
    Saves a new user to the database with hashed password and salt.
    Args:
        username (str): The user's username.
        image_path (str): Path to the user's image.
        password (str): The user's password.
    Returns:
        tuple: A tuple containing a boolean for success and a message.
    """
    pwdhash, salt = hash_password(password)
    try:
        with create_connection() as conn:
            if conn is None:
                return False, "Database connection failed."
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, image_path, password_hash, salt) VALUES (?, ?, ?, ?)",
                           (username, image_path, pwdhash, salt))
            conn.commit()
            return True, "User saved successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    except Exception as e:
        logging.error(f"Error saving user: {e}")
        return False, "Error occurred while saving user."

def verify_password(stored_hash, stored_salt, input_password):
    """
    Verifies a user's password.
    Args:
        stored_hash (bytes): The stored password hash.
        stored_salt (bytes): The stored salt used for hashing the password.
        input_password (str): The password provided by the user for verification.
    Returns:
        bool: True if the password is correct, False otherwise.
    """
    input_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode(), stored_salt, 100000)
    return input_hash == stored_hash

def verify_facial_recognition(stored_image_path, input_image_path):
    """
    Compares a stored image with a newly captured image to verify identity.
    Args:
        stored_image_path (str): Path to the stored image of the user.
        input_image_path (str): Path to the input image captured during login.
    Returns:
        bool: True if the faces match, False otherwise.
    """
    stored_image = face_recognition.load_image_file(stored_image_path)
    input_image = face_recognition.load_image_file(input_image_path)
    stored_encodings = face_recognition.face_encodings(stored_image)
    input_encodings = face_recognition.face_encodings(input_image)
    if not stored_encodings or not input_encodings:
        return False  # No face encodings found
    return face_recognition.compare_faces([stored_encodings[0]], input_encodings[0])[0]


def clear_all_users():
    """
    Deletes all users from the database and their associated image files.
    """
    try:
        with create_connection() as conn:
            if conn is None:
                return "Database connection failed."
            cursor = conn.cursor()
            cursor.execute("SELECT image_path FROM users")
            all_images = cursor.fetchall()
            for image in all_images:
                os.remove(image[0])
            cursor.execute("DELETE FROM users")
            conn.commit()
            return "All users cleared successfully."
    except sqlite3.Error as e:
        logging.error(f"Error clearing all users: {e}")
    except OSError as e:
        logging.error(f"Error removing image files: {e}")
    return "Error occurred during clearing users."


# Ensure the database is set up on first import
setup_database()
