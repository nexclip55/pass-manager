# Secure Password Manager

A secure password management application with a graphical user interface built in Python.

## Features

- **Secure Password Storage**: All passwords are encrypted using strong encryption (Fernet)
- **HMAC Verification**: Protects against tampering with stored passwords
- **Password Generation**: Generate strong, random passwords with customizable options
- **Password Strength Checking**: Visual indicator of password strength with feedback
- **Multiple User Accounts**: Support for multiple users with separate encrypted password storage
- **User-Friendly GUI**: Easy-to-use graphical interface built with Tkinter
- **Copy to Clipboard**: Quickly copy usernames and passwords to clipboard
- **Search Functionality**: Find passwords quickly with search feature

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-password-manager.git
   cd secure-password-manager
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python main.py
   ```

## Usage

### Registration
1. Launch the application
2. Go to the "Register" tab
3. Enter a username and master password
4. Click "Register"

### Login
1. Launch the application
2. Enter your username and master password
3. Click "Login"

### Adding a Password
1. Click "Add New" in the main interface
2. Fill in the details (title, website, username, password)
3. Optionally generate a password using the "Generate" button
4. Click "Save Changes"

### Viewing/Editing a Password
1. Select a password from the list
2. View or edit the details in the form
3. Click "Save Changes" to update

### Generating a Password
1. When adding or editing a password, click the "Generate" button
2. Customize the password options (length, character sets)
3. Click "Generate" to create a new password
4. Click "Use Password" to apply it

### Copying to Clipboard
1. Select a password from the list
2. Click the "Copy" button next to the username or password field

### Changing Master Password
1. Click on "Account" in the menu bar
2. Select "Change Master Password"
3. Enter your current password and new password
4. Click "Change Password"

### Managing HMAC Verification
1. Click on "Account" in the menu bar
2. Select "HMAC Settings"
3. Choose "Enable HMAC Verification" or "Disable HMAC Verification"
4. Enter your master password to confirm the action

## Security Features

- **Encryption**: All passwords are encrypted using Fernet symmetric encryption
- **HMAC Verification**: Ensures data integrity and authenticity of stored passwords
- **Key Derivation**: Master password is never stored directly; a key is derived using Argon2id
- **Salt**: Unique salt is used for each user to prevent rainbow table attacks
- **Password Hashing**: Master passwords are hashed using Argon2id with salt
- **Memory-Hard Algorithm**: Argon2id provides resistance against GPU-based attacks
- **No Plaintext Storage**: Passwords are only decrypted when needed and never stored in plaintext
- **Tamper Detection**: HMAC verification alerts users if stored passwords have been modified

## Requirements

- Python 3.6+
- cryptography
- pyperclip
- argon2-cffi

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The cryptography library for secure encryption
- Tkinter for the GUI framework