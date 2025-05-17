"""
Password utilities module.
Provides functions for password generation and strength checking.
"""
import random
import string
import re


class PasswordUtils:
    """Utilities for password generation and strength checking."""
    
    @staticmethod
    def generate_password(length=12, include_uppercase=True, include_lowercase=True,
                         include_numbers=True, include_special=True):
        """
        Generate a random password with specified characteristics.
        
        Args:
            length (int): Length of the password
            include_uppercase (bool): Include uppercase letters
            include_lowercase (bool): Include lowercase letters
            include_numbers (bool): Include numbers
            include_special (bool): Include special characters
            
        Returns:
            str: Generated password
        """
        # Define character sets
        chars = ""
        if include_uppercase:
            chars += string.ascii_uppercase
        if include_lowercase:
            chars += string.ascii_lowercase
        if include_numbers:
            chars += string.digits
        if include_special:
            chars += string.punctuation
            
        # Ensure at least one character set is selected
        if not chars:
            chars = string.ascii_letters + string.digits
            
        # Generate password
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Ensure the password contains at least one character from each selected set
        if include_uppercase and not any(c in string.ascii_uppercase for c in password):
            password = PasswordUtils._replace_random_char(password, string.ascii_uppercase)
            
        if include_lowercase and not any(c in string.ascii_lowercase for c in password):
            password = PasswordUtils._replace_random_char(password, string.ascii_lowercase)
            
        if include_numbers and not any(c in string.digits for c in password):
            password = PasswordUtils._replace_random_char(password, string.digits)
            
        if include_special and not any(c in string.punctuation for c in password):
            password = PasswordUtils._replace_random_char(password, string.punctuation)
            
        return password
    
    @staticmethod
    def _replace_random_char(password, char_set):
        """Replace a random character in the password with one from the given character set."""
        if not password:
            return random.choice(char_set)
            
        index = random.randint(0, len(password) - 1)
        password_list = list(password)
        password_list[index] = random.choice(char_set)
        return ''.join(password_list)
    
    @staticmethod
    def check_password_strength(password):
        """
        Check the strength of a password.
        
        Args:
            password (str): Password to check
            
        Returns:
            tuple: (score, feedback) where score is an integer from 0-5 and feedback is a string
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            feedback.append("Password is too short (minimum 8 characters)")
        elif len(password) >= 12:
            score += 1
            
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[^A-Za-z0-9]', password):
            score += 1
        else:
            feedback.append("Add special characters")
            
        # Common patterns check
        if re.search(r'(.)\1\1', password):  # Three or more repeated characters
            score -= 1
            feedback.append("Avoid repeated characters")
            
        if re.search(r'(123|234|345|456|567|678|789|987|876|765|654|543|432|321)', password):
            score -= 1
            feedback.append("Avoid sequential numbers")
            
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', 
                    password.lower()):
            score -= 1
            feedback.append("Avoid sequential letters")
            
        # Ensure score is within range
        score = max(0, min(score, 5))
        
        # Overall assessment
        strength_labels = ["Very Weak", "Weak", "Moderate", "Good", "Strong", "Very Strong"]
        
        if not feedback:
            feedback.append("Password is strong")
            
        return score, strength_labels[score], feedback