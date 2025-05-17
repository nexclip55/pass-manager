"""
Database module for the password manager.
Handles storage and retrieval of encrypted passwords and user data.
"""
import json
import os
import sqlite3
from encryption import Encryption


class Database:
    """Database handler for the password manager."""
    
    def __init__(self, db_path="password_manager.db"):
        """
        Initialize the database.
        
        Args:
            db_path (str): Path to the database file
        """
        self.db_path = db_path
        self._create_tables()
        self._migrate_database()
    
    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table with basic structure
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create passwords table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            website TEXT,
            username TEXT,
            password_encrypted BLOB NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def _migrate_database(self):
        """Migrate the database schema to the latest version."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if hmac_salt column exists in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add hmac_salt and hmac_enabled columns if they don't exist
        if "hmac_salt" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN hmac_salt BLOB")
        
        if "hmac_enabled" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN hmac_enabled INTEGER DEFAULT 0")
        
        conn.commit()
        conn.close()
    
    def add_user(self, username, password_hash, salt):
        """
        Add a new user to the database.
        
        Args:
            username (str): Username
            password_hash (str): Hashed master password
            salt (bytes): Salt used for password hashing
            
        Returns:
            int: User ID if successful, None if failed
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            # Username already exists
            return None
    
    def get_user(self, username):
        """
        Get user data by username.
        
        Args:
            username (str): Username to look up
            
        Returns:
            dict: User data if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, username, password_hash, salt, hmac_salt, hmac_enabled 
            FROM users WHERE username = ?
            """,
            (username,)
        )
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                "id": user[0],
                "username": user[1],
                "password_hash": user[2],
                "salt": user[3],
                "hmac_salt": user[4],
                "hmac_enabled": bool(user[5]) if user[5] is not None else False
            }
        return None
    
    def add_password(self, user_id, title, website, username, encrypted_password, notes=""):
        """
        Add a new password entry.
        
        Args:
            user_id (int): User ID
            title (str): Entry title
            website (str): Website URL
            username (str): Username for the website
            encrypted_password (bytes): Encrypted password (may include HMAC)
            notes (str): Additional notes
            
        Returns:
            int: Entry ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """
            INSERT INTO passwords 
            (user_id, title, website, username, password_encrypted, notes) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, title, website, username, encrypted_password, notes)
        )
        
        entry_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return entry_id
    
    def update_password(self, entry_id, title=None, website=None, username=None, 
                       encrypted_password=None, notes=None):
        """
        Update a password entry.
        
        Args:
            entry_id (int): Entry ID to update
            title (str, optional): New title
            website (str, optional): New website URL
            username (str, optional): New username
            encrypted_password (bytes, optional): New encrypted password (may include HMAC)
            notes (str, optional): New notes
            
        Returns:
            bool: True if successful, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build update query dynamically based on provided parameters
        update_parts = []
        params = []
        
        if title is not None:
            update_parts.append("title = ?")
            params.append(title)
            
        if website is not None:
            update_parts.append("website = ?")
            params.append(website)
            
        if username is not None:
            update_parts.append("username = ?")
            params.append(username)
            
        if encrypted_password is not None:
            update_parts.append("password_encrypted = ?")
            params.append(encrypted_password)
            
        if notes is not None:
            update_parts.append("notes = ?")
            params.append(notes)
            
        if not update_parts:
            conn.close()
            return False
            
        update_parts.append("updated_at = CURRENT_TIMESTAMP")
        
        query = f"UPDATE passwords SET {', '.join(update_parts)} WHERE id = ?"
        params.append(entry_id)
        
        cursor.execute(query, params)
        success = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return success
    
    def delete_password(self, entry_id):
        """
        Delete a password entry.
        
        Args:
            entry_id (int): Entry ID to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        success = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return success
    
    def get_passwords(self, user_id):
        """
        Get all password entries for a user.
        
        Args:
            user_id (int): User ID
            
        Returns:
            list: List of password entries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, title, website, username, password_encrypted, notes, created_at, updated_at
            FROM passwords
            WHERE user_id = ?
            ORDER BY title
            """,
            (user_id,)
        )
        
        entries = cursor.fetchall()
        conn.close()
        
        result = []
        for entry in entries:
            result.append({
                "id": entry[0],
                "title": entry[1],
                "website": entry[2],
                "username": entry[3],
                "password_encrypted": entry[4],
                "notes": entry[5],
                "created_at": entry[6],
                "updated_at": entry[7]
            })
            
        return result
    
    def get_password(self, entry_id):
        """
        Get a specific password entry.
        
        Args:
            entry_id (int): Entry ID
            
        Returns:
            dict: Password entry if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, user_id, title, website, username, password_encrypted, notes, created_at, updated_at
            FROM passwords
            WHERE id = ?
            """,
            (entry_id,)
        )
        
        entry = cursor.fetchone()
        conn.close()
        
        if entry:
            return {
                "id": entry[0],
                "user_id": entry[1],
                "title": entry[2],
                "website": entry[3],
                "username": entry[4],
                "password_encrypted": entry[5],
                "notes": entry[6],
                "created_at": entry[7],
                "updated_at": entry[8]
            }
        return None