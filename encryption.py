"""
Encryption module for the password manager.
Handles encryption and decryption of sensitive data with HMAC verification.
Uses Argon2id for key derivation.
"""
import base64
import os
import hmac
import hashlib
import json
from cryptography.fernet import Fernet
import argon2
from argon2.profiles import RFC_9106_LOW_MEMORY


class Encryption:
    """Handles encryption and decryption of data with HMAC verification using Argon2id."""
    
    # Argon2id parameters
    # Using RFC 9106 low memory profile as a baseline
    # These parameters can be adjusted based on the target hardware
    ARGON2_TIME_COST = RFC_9106_LOW_MEMORY.time_cost  # Number of iterations
    ARGON2_MEMORY_COST = RFC_9106_LOW_MEMORY.memory_cost  # Memory usage in kibibytes
    ARGON2_PARALLELISM = RFC_9106_LOW_MEMORY.parallelism  # Number of parallel threads
    ARGON2_HASH_LEN = 32  # Output hash length in bytes
    
    @staticmethod
    def generate_key(master_password, salt=None):
        """
        Generate an encryption key from the master password using Argon2id.
        
        Args:
            master_password (str): The master password to derive the key from
            salt (bytes, optional): Salt for key derivation. If None, a new one is generated.
            
        Returns:
            tuple: (key, salt) where key is the encryption key and salt is the salt used
        """
        if salt is None:
            salt = os.urandom(16)
        
        # Convert password to bytes if it's a string
        if isinstance(master_password, str):
            master_password = master_password.encode()
            
        # Use Argon2id to derive a key from the password
        hasher = argon2.low_level.hash_secret_raw(
            secret=master_password,
            salt=salt,
            time_cost=Encryption.ARGON2_TIME_COST,
            memory_cost=Encryption.ARGON2_MEMORY_COST,
            parallelism=Encryption.ARGON2_PARALLELISM,
            hash_len=Encryption.ARGON2_HASH_LEN,
            type=argon2.Type.ID  # Argon2id variant
        )
        
        # Fernet requires a URL-safe base64-encoded 32-byte key
        key = base64.urlsafe_b64encode(hasher)
        return key, salt
    
    @staticmethod
    def generate_hmac_key(master_password, salt):
        """
        Generate an HMAC key from the master password using Argon2id.
        This key is different from the encryption key to maintain separation of concerns.
        
        Args:
            master_password (str): The master password to derive the key from
            salt (bytes): Salt for key derivation
            
        Returns:
            bytes: HMAC key
        """
        # Convert password to bytes if it's a string
        if isinstance(master_password, str):
            master_password = master_password.encode()
            
        # Add a suffix to ensure a different key than the encryption key
        hmac_password = master_password + b"hmac_key"
        
        # Use Argon2id with slightly different parameters for the HMAC key
        hmac_key = argon2.low_level.hash_secret_raw(
            secret=hmac_password,
            salt=salt,
            time_cost=Encryption.ARGON2_TIME_COST + 1,  # Slightly different time cost
            memory_cost=Encryption.ARGON2_MEMORY_COST,
            parallelism=Encryption.ARGON2_PARALLELISM,
            hash_len=Encryption.ARGON2_HASH_LEN,
            type=argon2.Type.ID  # Argon2id variant
        )
        
        return hmac_key
    
    @staticmethod
    def compute_hmac(data, hmac_key):
        """
        Compute HMAC for data.
        
        Args:
            data (bytes): Data to compute HMAC for
            hmac_key (bytes): HMAC key
            
        Returns:
            bytes: HMAC digest
        """
        return hmac.new(hmac_key, data, hashlib.sha256).digest()
    
    @staticmethod
    def encrypt_data(data, key, hmac_key=None):
        """
        Encrypt data using the provided key and add HMAC for integrity verification.
        
        Args:
            data (str): Data to encrypt
            key (bytes): Encryption key
            hmac_key (bytes, optional): Key for HMAC. If None, only encryption is performed.
            
        Returns:
            bytes: Encrypted data with HMAC
        """
        if isinstance(data, str):
            data = data.encode()
            
        # Encrypt the data
        f = Fernet(key)
        encrypted_data = f.encrypt(data)
        
        # If HMAC key is provided, add HMAC
        if hmac_key:
            hmac_digest = Encryption.compute_hmac(encrypted_data, hmac_key)
            
            # Combine encrypted data and HMAC
            result = {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "hmac": base64.b64encode(hmac_digest).decode()
            }
            return json.dumps(result).encode()
        
        return encrypted_data
    
    @staticmethod
    def decrypt_data(encrypted_data, key, hmac_key=None):
        """
        Decrypt data using the provided key and verify HMAC if provided.
        
        Args:
            encrypted_data (bytes): Data to decrypt
            key (bytes): Decryption key
            hmac_key (bytes, optional): Key for HMAC verification. If None, only decryption is performed.
            
        Returns:
            str: Decrypted data as a string
            
        Raises:
            ValueError: If HMAC verification fails
        """
        # Check if data includes HMAC
        if hmac_key:
            try:
                # Parse the JSON data
                data_dict = json.loads(encrypted_data.decode())
                encrypted_part = base64.b64decode(data_dict["encrypted_data"])
                stored_hmac = base64.b64decode(data_dict["hmac"])
                
                # Verify HMAC
                computed_hmac = Encryption.compute_hmac(encrypted_part, hmac_key)
                if not hmac.compare_digest(computed_hmac, stored_hmac):
                    raise ValueError("HMAC verification failed: Data may have been tampered with")
                
                # Decrypt the data
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_part)
                
            except (json.JSONDecodeError, KeyError, base64.binascii.Error):
                # If the data is not in the expected format, try to decrypt it directly
                # This handles backward compatibility with data encrypted without HMAC
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_data)
        else:
            # No HMAC key provided, just decrypt
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
        return decrypted_data.decode()
    
    @staticmethod
    def migrate_to_hmac(encrypted_data, key, hmac_key):
        """
        Migrate existing encrypted data to include HMAC.
        
        Args:
            encrypted_data (bytes): Previously encrypted data without HMAC
            key (bytes): Encryption key
            hmac_key (bytes): HMAC key
            
        Returns:
            bytes: Encrypted data with HMAC
        """
        # First decrypt the data
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        
        # Then re-encrypt with HMAC
        return Encryption.encrypt_data(decrypted_data, key, hmac_key)