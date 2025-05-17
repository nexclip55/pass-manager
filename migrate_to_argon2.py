"""
Migration script to update existing password hashes to use Argon2id.

This script should be run after updating the code to use Argon2id.
It will prompt for the master password of each user and update their password hash.
"""
import sqlite3
import getpass
import os
import base64
import hashlib
import argon2
from argon2.profiles import RFC_9106_LOW_MEMORY


def hash_password_sha256(password, salt):
    """
    Hash a password with salt using SHA-256 (old method).
    
    Args:
        password (str): Password to hash
        salt (bytes): Salt for hashing
        
    Returns:
        str: Base64-encoded password hash
    """
    if isinstance(password, str):
        password = password.encode()
        
    # Hash the password with salt using SHA-256
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(password)
    
    # Return base64-encoded hash
    return base64.b64encode(hasher.digest()).decode()


def hash_password_argon2id(password, salt):
    """
    Hash a password with salt using Argon2id (new method).
    
    Args:
        password (str): Password to hash
        salt (bytes): Salt for hashing
        
    Returns:
        str: Base64-encoded password hash
    """
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


def migrate_users(db_path="password_manager.db"):
    """
    Migrate all users to use Argon2id for password hashing.
    
    Args:
        db_path (str): Path to the database file
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT id, username, password_hash, salt FROM users")
    users = cursor.fetchall()
    
    if not users:
        print("No users found in the database.")
        conn.close()
        return
    
    print(f"Found {len(users)} user(s) in the database.")
    print("This script will update password hashes to use Argon2id.")
    print("You will need to enter the master password for each user.")
    print()
    
    for user_id, username, old_hash, salt in users:
        print(f"Updating user: {username}")
        
        # Ask for the master password
        password = getpass.getpass(f"Enter master password for {username}: ")
        
        # Verify the password using the old hashing method
        verify_hash = hash_password_sha256(password, salt)
        if verify_hash != old_hash:
            print(f"Incorrect password for {username}. Skipping.")
            continue
        
        # Generate new hash using Argon2id
        new_hash = hash_password_argon2id(password, salt)
        
        # Update the user's password hash
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id)
        )
        
        print(f"Updated password hash for {username}.")
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print()
    print("Migration completed successfully.")


if __name__ == "__main__":
    migrate_users()