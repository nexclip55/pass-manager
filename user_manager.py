"""
User management module for the password manager.
Handles user authentication, registration, and session management.
Uses Argon2id for password hashing.
"""
import os
import base64
import sqlite3
import argon2
from argon2.profiles import RFC_9106_LOW_MEMORY
from database import Database
from encryption import Encryption


class UserManager:
    """Manages user accounts and authentication."""
    
    def __init__(self, database):
        """
        Initialize the user manager.
        
        Args:
            database (Database): Database instance
        """
        self.database = database
        self.current_user = None
        self.encryption_key = None
        self.hmac_key = None
    
    def register_user(self, username, master_password, enable_hmac=True):
        """
        Register a new user.
        
        Args:
            username (str): Username
            master_password (str): Master password
            enable_hmac (bool): Whether to enable HMAC verification
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        # Check if username already exists
        if self.database.get_user(username):
            return False
        
        # Generate salt for password hashing
        salt = os.urandom(16)
        
        # Hash the master password
        password_hash = self._hash_password(master_password, salt)
        
        # Generate HMAC salt if HMAC is enabled
        hmac_salt = os.urandom(16) if enable_hmac else None
        hmac_enabled = 1 if enable_hmac else 0
        
        # Add user to database with HMAC information
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """
                INSERT INTO users 
                (username, password_hash, salt, hmac_salt, hmac_enabled) 
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, password_hash, salt, hmac_salt, hmac_enabled)
            )
            
            user_id = cursor.lastrowid
            conn.commit()
            return user_id is not None
            
        except sqlite3.IntegrityError:
            # Username already exists
            return False
            
        finally:
            conn.close()
    
    def login(self, username, master_password):
        """
        Log in a user.
        
        Args:
            username (str): Username
            master_password (str): Master password
            
        Returns:
            bool: True if login successful, False otherwise
        """
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, username, password_hash, salt, hmac_salt, hmac_enabled
            FROM users WHERE username = ?
            """,
            (username,)
        )
        
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            return False
        
        # Create user dictionary
        user = {
            "id": user_data[0],
            "username": user_data[1],
            "password_hash": user_data[2],
            "salt": user_data[3],
            "hmac_salt": user_data[4],
            "hmac_enabled": bool(user_data[5])
        }
        
        # Verify password
        password_hash = self._hash_password(master_password, user["salt"])
        if password_hash != user["password_hash"]:
            return False
        
        # Set current user and generate encryption key
        self.current_user = user
        key, _ = Encryption.generate_key(master_password, user["salt"])
        self.encryption_key = key
        
        # Generate HMAC key if HMAC is enabled
        if user["hmac_enabled"] and user["hmac_salt"]:
            self.hmac_key = Encryption.generate_hmac_key(master_password, user["hmac_salt"])
        else:
            self.hmac_key = None
        
        return True
    
    def logout(self):
        """Log out the current user."""
        self.current_user = None
        self.encryption_key = None
        self.hmac_key = None
    
    def is_logged_in(self):
        """
        Check if a user is currently logged in.
        
        Returns:
            bool: True if a user is logged in, False otherwise
        """
        return self.current_user is not None
    
    def get_current_user(self):
        """
        Get the current logged-in user.
        
        Returns:
            dict: Current user data if logged in, None otherwise
        """
        return self.current_user
    
    def is_hmac_enabled(self):
        """
        Check if HMAC verification is enabled for the current user.
        
        Returns:
            bool: True if HMAC is enabled, False otherwise
        """
        if not self.is_logged_in():
            return False
        return self.current_user.get("hmac_enabled", False)
    
    def enable_hmac(self, master_password):
        """
        Enable HMAC verification for the current user.
        
        Args:
            master_password (str): Master password to verify user
            
        Returns:
            bool: True if HMAC was enabled successfully, False otherwise
        """
        if not self.is_logged_in():
            return False
            
        # Verify password
        password_hash = self._hash_password(master_password, self.current_user["salt"])
        if password_hash != self.current_user["password_hash"]:
            return False
            
        # If HMAC is already enabled, nothing to do
        if self.is_hmac_enabled() and self.current_user.get("hmac_salt"):
            return True
            
        # Generate HMAC salt
        hmac_salt = os.urandom(16)
        
        # Generate HMAC key
        hmac_key = Encryption.generate_hmac_key(master_password, hmac_salt)
        
        # Get all passwords for the current user
        passwords = self.database.get_passwords(self.current_user["id"])
        
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        
        try:
            # Start transaction
            conn.execute("BEGIN TRANSACTION")
            
            # Update user's HMAC settings
            cursor.execute(
                "UPDATE users SET hmac_salt = ?, hmac_enabled = 1 WHERE id = ?",
                (hmac_salt, self.current_user["id"])
            )
            
            # Re-encrypt all passwords with HMAC
            for entry in passwords:
                # Decrypt with current key
                decrypted = Encryption.decrypt_data(entry["password_encrypted"], self.encryption_key)
                
                # Re-encrypt with HMAC
                encrypted = Encryption.encrypt_data(decrypted, self.encryption_key, hmac_key)
                
                # Update in database
                cursor.execute(
                    "UPDATE passwords SET password_encrypted = ? WHERE id = ?",
                    (encrypted, entry["id"])
                )
            
            # Commit transaction
            conn.commit()
            
            # Update current user and HMAC key
            self.current_user["hmac_salt"] = hmac_salt
            self.current_user["hmac_enabled"] = True
            self.hmac_key = hmac_key
            
            return True
            
        except Exception as e:
            # Rollback on error
            conn.rollback()
            return False
            
        finally:
            conn.close()
    
    def disable_hmac(self, master_password):
        """
        Disable HMAC verification for the current user.
        
        Args:
            master_password (str): Master password to verify user
            
        Returns:
            bool: True if HMAC was disabled successfully, False otherwise
        """
        if not self.is_logged_in() or not self.is_hmac_enabled():
            return False
            
        # Verify password
        password_hash = self._hash_password(master_password, self.current_user["salt"])
        if password_hash != self.current_user["password_hash"]:
            return False
            
        # Get all passwords for the current user
        passwords = self.database.get_passwords(self.current_user["id"])
        
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        
        try:
            # Start transaction
            conn.execute("BEGIN TRANSACTION")
            
            # Update user's HMAC settings
            cursor.execute(
                "UPDATE users SET hmac_enabled = 0 WHERE id = ?",
                (self.current_user["id"],)
            )
            
            # Re-encrypt all passwords without HMAC
            for entry in passwords:
                try:
                    # Decrypt with current key and HMAC verification
                    decrypted = Encryption.decrypt_data(
                        entry["password_encrypted"], 
                        self.encryption_key, 
                        self.hmac_key
                    )
                    
                    # Re-encrypt without HMAC
                    encrypted = Encryption.encrypt_data(decrypted, self.encryption_key)
                    
                    # Update in database
                    cursor.execute(
                        "UPDATE passwords SET password_encrypted = ? WHERE id = ?",
                        (encrypted, entry["id"])
                    )
                except Exception as e:
                    # If decryption fails, try without HMAC verification
                    # This handles the case where some passwords might not have HMAC
                    try:
                        decrypted = Encryption.decrypt_data(
                            entry["password_encrypted"], 
                            self.encryption_key
                        )
                        
                        encrypted = Encryption.encrypt_data(decrypted, self.encryption_key)
                        
                        cursor.execute(
                            "UPDATE passwords SET password_encrypted = ? WHERE id = ?",
                            (encrypted, entry["id"])
                        )
                    except:
                        # If both methods fail, skip this password
                        continue
            
            # Commit transaction
            conn.commit()
            
            # Update current user
            self.current_user["hmac_enabled"] = False
            self.hmac_key = None
            
            return True
            
        except Exception as e:
            # Rollback on error
            conn.rollback()
            return False
            
        finally:
            conn.close()
    
    def change_master_password(self, old_password, new_password):
        """
        Change the master password for the current user.
        
        Args:
            old_password (str): Current master password
            new_password (str): New master password
            
        Returns:
            bool: True if password change successful, False otherwise
        """
        if not self.is_logged_in():
            return False
        
        # Verify old password
        old_hash = self._hash_password(old_password, self.current_user["salt"])
        if old_hash != self.current_user["password_hash"]:
            return False
        
        # Generate new salt and hash
        new_salt = os.urandom(16)
        new_hash = self._hash_password(new_password, new_salt)
        
        # Generate new HMAC salt if HMAC is enabled
        new_hmac_salt = os.urandom(16) if self.is_hmac_enabled() else None
        
        # Get all passwords for the current user
        passwords = self.database.get_passwords(self.current_user["id"])
        
        # Generate old and new encryption keys
        old_key, _ = Encryption.generate_key(old_password, self.current_user["salt"])
        new_key, _ = Encryption.generate_key(new_password, new_salt)
        
        # Generate old and new HMAC keys if HMAC is enabled
        old_hmac_key = self.hmac_key
        new_hmac_key = None
        if self.is_hmac_enabled() and new_hmac_salt:
            new_hmac_key = Encryption.generate_hmac_key(new_password, new_hmac_salt)
        
        # Re-encrypt all passwords with the new keys
        conn = sqlite3.connect(self.database.db_path)
        cursor = conn.cursor()
        
        try:
            # Start transaction
            conn.execute("BEGIN TRANSACTION")
            
            # Update user's password hash, salt, and HMAC salt
            if self.is_hmac_enabled() and new_hmac_salt:
                cursor.execute(
                    "UPDATE users SET password_hash = ?, salt = ?, hmac_salt = ? WHERE id = ?",
                    (new_hash, new_salt, new_hmac_salt, self.current_user["id"])
                )
            else:
                cursor.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                    (new_hash, new_salt, self.current_user["id"])
                )
            
            # Re-encrypt all passwords
            for entry in passwords:
                try:
                    # Decrypt with old keys
                    if old_hmac_key:
                        decrypted = Encryption.decrypt_data(
                            entry["password_encrypted"], 
                            old_key, 
                            old_hmac_key
                        )
                    else:
                        decrypted = Encryption.decrypt_data(
                            entry["password_encrypted"], 
                            old_key
                        )
                    
                    # Encrypt with new keys
                    if new_hmac_key:
                        encrypted = Encryption.encrypt_data(
                            decrypted, 
                            new_key, 
                            new_hmac_key
                        )
                    else:
                        encrypted = Encryption.encrypt_data(
                            decrypted, 
                            new_key
                        )
                    
                    # Update in database
                    cursor.execute(
                        "UPDATE passwords SET password_encrypted = ? WHERE id = ?",
                        (encrypted, entry["id"])
                    )
                except Exception as e:
                    # If decryption fails, try without HMAC verification
                    try:
                        decrypted = Encryption.decrypt_data(
                            entry["password_encrypted"], 
                            old_key
                        )
                        
                        if new_hmac_key:
                            encrypted = Encryption.encrypt_data(
                                decrypted, 
                                new_key, 
                                new_hmac_key
                            )
                        else:
                            encrypted = Encryption.encrypt_data(
                                decrypted, 
                                new_key
                            )
                        
                        cursor.execute(
                            "UPDATE passwords SET password_encrypted = ? WHERE id = ?",
                            (encrypted, entry["id"])
                        )
                    except:
                        # If both methods fail, skip this password
                        continue
            
            # Commit transaction
            conn.commit()
            
            # Update current user and keys
            self.current_user["password_hash"] = new_hash
            self.current_user["salt"] = new_salt
            if self.is_hmac_enabled() and new_hmac_salt:
                self.current_user["hmac_salt"] = new_hmac_salt
            
            self.encryption_key = new_key
            self.hmac_key = new_hmac_key
            
            return True
            
        except Exception as e:
            # Rollback on error
            conn.rollback()
            return False
            
        finally:
            conn.close()
    
    @staticmethod
    def _hash_password(password, salt):
        """
        Hash a password with the given salt using Argon2id.
        
        Args:
            password (str): Password to hash
            salt (bytes): Salt for hashing
            
        Returns:
            str: Base64-encoded password hash
        """
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode()
            
        # Hash the password with Argon2id
        hash_bytes = argon2.low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=RFC_9106_LOW_MEMORY.time_cost,
            memory_cost=RFC_9106_LOW_MEMORY.memory_cost,
            parallelism=RFC_9106_LOW_MEMORY.parallelism,
            hash_len=32,
            type=argon2.Type.ID
        )
        
        # Return base64-encoded hash
        return base64.b64encode(hash_bytes).decode()