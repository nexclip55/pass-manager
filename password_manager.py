"""
Password Manager Application.
A secure password management system with GUI.
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import pyperclip
from database import Database
from user_manager import UserManager
from password_utils import PasswordUtils
from encryption import Encryption


class PasswordManagerApp:
    """Main password manager application with GUI."""
    
    def __init__(self, root):
        """
        Initialize the password manager application.
        
        Args:
            root (tk.Tk): Root Tkinter window
        """
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Initialize database and user manager
        self.database = Database()
        self.user_manager = UserManager(self.database)
        
        # Set up the UI
        self._setup_styles()
        self._create_menu()
        self._create_login_frame()
        self._create_main_frame()
        
        # Start with login frame
        self.show_login_frame()
    
    def _setup_styles(self):
        """Set up ttk styles for the application."""
        style = ttk.Style()
        
        # Configure common styles
        style.configure("TLabel", font=("Arial", 11))
        style.configure("TButton", font=("Arial", 11))
        style.configure("TEntry", font=("Arial", 11))
        
        # Configure specific styles
        style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        style.configure("Success.TLabel", foreground="green")
        style.configure("Error.TLabel", foreground="red")
        
        # Configure progress bar styles for password strength
        style.configure("Red.Horizontal.TProgressbar", 
                       background="red", troughcolor="light gray")
        style.configure("Yellow.Horizontal.TProgressbar", 
                       background="yellow", troughcolor="light gray")
        style.configure("Green.Horizontal.TProgressbar", 
                       background="green", troughcolor="light gray")
    
    def _create_menu(self):
        """Create the application menu."""
        self.menu_bar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Account menu (will be populated when logged in)
        self.account_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.account_menu.add_command(label="Change Master Password", 
                                     command=self._change_master_password)
        
        # HMAC submenu
        self.hmac_menu = tk.Menu(self.account_menu, tearoff=0)
        self.hmac_menu.add_command(label="Enable HMAC Verification", 
                                  command=self._enable_hmac)
        self.hmac_menu.add_command(label="Disable HMAC Verification", 
                                  command=self._disable_hmac)
        self.account_menu.add_cascade(label="HMAC Settings", menu=self.hmac_menu)
        
        self.account_menu.add_separator()
        self.account_menu.add_command(label="Logout", command=self._logout)
        
        # Help menu
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=self.menu_bar)
    
    def _create_login_frame(self):
        """Create the login/register frame."""
        self.login_frame = ttk.Frame(self.root, padding=20)
        
        # Title
        ttk.Label(self.login_frame, text="Secure Password Manager", 
                 style="Title.TLabel").pack(pady=20)
        
        # Notebook for login/register tabs
        notebook = ttk.Notebook(self.login_frame)
        
        # Login tab
        login_tab = ttk.Frame(notebook, padding=10)
        notebook.add(login_tab, text="Login")
        
        ttk.Label(login_tab, text="Username:").pack(pady=(10, 5), anchor="w")
        self.login_username = ttk.Entry(login_tab, width=30)
        self.login_username.pack(pady=5, fill="x")
        
        ttk.Label(login_tab, text="Master Password:").pack(pady=(10, 5), anchor="w")
        self.login_password = ttk.Entry(login_tab, width=30, show="•")
        self.login_password.pack(pady=5, fill="x")
        
        ttk.Button(login_tab, text="Login", command=self._login).pack(pady=20)
        
        # Register tab
        register_tab = ttk.Frame(notebook, padding=10)
        notebook.add(register_tab, text="Register")
        
        ttk.Label(register_tab, text="Username:").pack(pady=(10, 5), anchor="w")
        self.register_username = ttk.Entry(register_tab, width=30)
        self.register_username.pack(pady=5, fill="x")
        
        ttk.Label(register_tab, text="Master Password:").pack(pady=(10, 5), anchor="w")
        self.register_password = ttk.Entry(register_tab, width=30, show="•")
        self.register_password.pack(pady=5, fill="x")
        
        ttk.Label(register_tab, text="Confirm Password:").pack(pady=(10, 5), anchor="w")
        self.register_confirm = ttk.Entry(register_tab, width=30, show="•")
        self.register_confirm.pack(pady=5, fill="x")
        
        ttk.Button(register_tab, text="Register", command=self._register).pack(pady=20)
        
        notebook.pack(expand=True, fill="both")
        
        # Status message
        self.login_status = ttk.Label(self.login_frame, text="")
        self.login_status.pack(pady=10)
    
    def _create_main_frame(self):
        """Create the main application frame."""
        self.main_frame = ttk.Frame(self.root, padding=10)
        
        # Split into left and right panes
        paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left pane - password list
        left_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(left_frame, weight=1)
        
        # Search bar
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", self._filter_passwords)
        
        # Password list with scrollbar
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.password_listbox = tk.Listbox(list_frame, font=("Arial", 11))
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, 
                                 command=self.password_listbox.yview)
        self.password_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.password_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.password_listbox.bind("<<ListboxSelect>>", self._on_password_select)
        
        # Buttons below list
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Add New", command=self._add_password).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self._delete_password).pack(
            side=tk.LEFT, padx=5)
        
        # Right pane - password details
        right_frame = ttk.Frame(paned_window, padding=5)
        paned_window.add(right_frame, weight=2)
        
        # Details form
        ttk.Label(right_frame, text="Password Details", 
                 style="Header.TLabel").grid(row=0, column=0, columnspan=2, 
                                           sticky="w", pady=(0, 10))
        
        # Title
        ttk.Label(right_frame, text="Title:").grid(row=1, column=0, sticky="w", pady=5)
        self.title_var = tk.StringVar()
        ttk.Entry(right_frame, textvariable=self.title_var).grid(
            row=1, column=1, sticky="ew", pady=5)
        
        # Website
        ttk.Label(right_frame, text="Website:").grid(row=2, column=0, sticky="w", pady=5)
        self.website_var = tk.StringVar()
        ttk.Entry(right_frame, textvariable=self.website_var).grid(
            row=2, column=1, sticky="ew", pady=5)
        
        # Username
        ttk.Label(right_frame, text="Username:").grid(row=3, column=0, sticky="w", pady=5)
        self.username_var = tk.StringVar()
        username_frame = ttk.Frame(right_frame)
        username_frame.grid(row=3, column=1, sticky="ew", pady=5)
        
        ttk.Entry(username_frame, textvariable=self.username_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(username_frame, text="Copy", width=8, 
                  command=lambda: self._copy_to_clipboard(self.username_var.get())).pack(
            side=tk.RIGHT, padx=(5, 0))
        
        # Password
        ttk.Label(right_frame, text="Password:").grid(row=4, column=0, sticky="w", pady=5)
        self.password_var = tk.StringVar()
        password_frame = ttk.Frame(right_frame)
        password_frame.grid(row=4, column=1, sticky="ew", pady=5)
        
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(password_frame, text="Show", variable=self.show_password_var, 
                       command=self._toggle_password_visibility).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(password_frame, text="Copy", width=8, 
                  command=lambda: self._copy_to_clipboard(self.password_var.get())).pack(
            side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(password_frame, text="Generate", width=8, 
                  command=self._generate_password).pack(side=tk.LEFT)
        
        # Notes
        ttk.Label(right_frame, text="Notes:").grid(row=5, column=0, sticky="nw", pady=5)
        self.notes_var = tk.StringVar()
        self.notes_text = tk.Text(right_frame, height=5, width=40, font=("Arial", 11))
        self.notes_text.grid(row=5, column=1, sticky="ew", pady=5)
        
        # Password strength meter
        ttk.Label(right_frame, text="Password Strength:").grid(
            row=6, column=0, sticky="w", pady=5)
        
        strength_frame = ttk.Frame(right_frame)
        strength_frame.grid(row=6, column=1, sticky="ew", pady=5)
        
        self.strength_meter = ttk.Progressbar(strength_frame, length=200, mode="determinate")
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.strength_label = ttk.Label(strength_frame, text="")
        self.strength_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Save button
        ttk.Button(right_frame, text="Save Changes", command=self._save_password).grid(
            row=7, column=0, columnspan=2, pady=10)
        
        # Configure grid weights
        right_frame.columnconfigure(1, weight=1)
        
        # Initialize password list
        self.password_entries = []
        self.current_entry_id = None
    
    def show_login_frame(self):
        """Show the login frame."""
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Remove Account menu if it exists
        try:
            self.menu_bar.delete("Account")
        except tk.TclError:
            # Menu item doesn't exist yet, which is fine
            pass
        
        # Clear login fields
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        self.register_username.delete(0, tk.END)
        self.register_password.delete(0, tk.END)
        self.register_confirm.delete(0, tk.END)
        self.login_status.config(text="")
    
    def show_main_frame(self):
        """Show the main application frame."""
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add Account menu
        self.menu_bar.add_cascade(label="Account", menu=self.account_menu)
        
        # Update HMAC menu items based on current status
        if self.user_manager.is_hmac_enabled():
            self.hmac_menu.entryconfig("Enable HMAC Verification", state=tk.DISABLED)
            self.hmac_menu.entryconfig("Disable HMAC Verification", state=tk.NORMAL)
        else:
            self.hmac_menu.entryconfig("Enable HMAC Verification", state=tk.NORMAL)
            self.hmac_menu.entryconfig("Disable HMAC Verification", state=tk.DISABLED)
        
        # Load passwords
        self._load_passwords()
        
        # Clear details form
        self._clear_details_form()
    
    def _login(self):
        """Handle user login."""
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            self.login_status.config(
                text="Please enter both username and password", style="Error.TLabel")
            return
        
        if self.user_manager.login(username, password):
            self.show_main_frame()
        else:
            self.login_status.config(
                text="Invalid username or password", style="Error.TLabel")
    
    def _register(self):
        """Handle user registration."""
        username = self.register_username.get()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        
        if not username or not password or not confirm:
            self.login_status.config(
                text="Please fill in all fields", style="Error.TLabel")
            return
        
        if password != confirm:
            self.login_status.config(
                text="Passwords do not match", style="Error.TLabel")
            return
        
        # Check password strength
        score, strength, feedback = PasswordUtils.check_password_strength(password)
        if score < 3:
            self.login_status.config(
                text=f"Password too weak: {', '.join(feedback)}", style="Error.TLabel")
            return
        
        if self.user_manager.register_user(username, password):
            self.login_status.config(
                text="Registration successful! You can now log in.", style="Success.TLabel")
        else:
            self.login_status.config(
                text="Username already exists", style="Error.TLabel")
    
    def _logout(self):
        """Handle user logout."""
        self.user_manager.logout()
        self.show_login_frame()
    
    def _change_master_password(self):
        """Handle changing the master password."""
        if not self.user_manager.is_logged_in():
            return
        
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Current Password:").pack(pady=(20, 5), anchor="w", padx=20)
        current_password = ttk.Entry(dialog, width=30, show="•")
        current_password.pack(pady=5, padx=20, fill="x")
        
        ttk.Label(dialog, text="New Password:").pack(pady=(10, 5), anchor="w", padx=20)
        new_password = ttk.Entry(dialog, width=30, show="•")
        new_password.pack(pady=5, padx=20, fill="x")
        
        ttk.Label(dialog, text="Confirm New Password:").pack(pady=(10, 5), anchor="w", padx=20)
        confirm_password = ttk.Entry(dialog, width=30, show="•")
        confirm_password.pack(pady=5, padx=20, fill="x")
        
        status_label = ttk.Label(dialog, text="")
        status_label.pack(pady=10, padx=20)
        
        def change_password():
            current = current_password.get()
            new = new_password.get()
            confirm = confirm_password.get()
            
            if not current or not new or not confirm:
                status_label.config(text="Please fill in all fields", foreground="red")
                return
            
            if new != confirm:
                status_label.config(text="New passwords do not match", foreground="red")
                return
            
            # Check password strength
            score, strength, feedback = PasswordUtils.check_password_strength(new)
            if score < 3:
                status_label.config(
                    text=f"Password too weak: {', '.join(feedback)}", foreground="red")
                return
            
            if self.user_manager.change_master_password(current, new):
                messagebox.showinfo("Success", "Master password changed successfully")
                dialog.destroy()
            else:
                status_label.config(text="Current password is incorrect", foreground="red")
        
        ttk.Button(dialog, text="Change Password", command=change_password).pack(pady=10)
    
    def _load_passwords(self):
        """Load passwords for the current user."""
        if not self.user_manager.is_logged_in():
            return
        
        # Get passwords from database
        user_id = self.user_manager.get_current_user()["id"]
        self.password_entries = self.database.get_passwords(user_id)
        
        # Update listbox
        self._update_password_list()
    
    def _update_password_list(self, filter_text=None):
        """
        Update the password list in the UI.
        
        Args:
            filter_text (str, optional): Text to filter the list by
        """
        self.password_listbox.delete(0, tk.END)
        
        for entry in self.password_entries:
            title = entry["title"]
            
            # Apply filter if provided
            if filter_text and filter_text.lower() not in title.lower():
                continue
                
            self.password_listbox.insert(tk.END, title)
    
    def _filter_passwords(self, event=None):
        """Filter the password list based on search text."""
        filter_text = self.search_entry.get()
        self._update_password_list(filter_text)
    
    def _on_password_select(self, event=None):
        """Handle password selection from the list."""
        selection = self.password_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        filter_text = self.search_entry.get()
        
        # Find the corresponding entry
        if filter_text:
            # If filtered, find the actual entry
            title = self.password_listbox.get(index)
            for entry in self.password_entries:
                if entry["title"] == title:
                    self._display_password_details(entry)
                    break
        else:
            # If not filtered, use the index directly
            if index < len(self.password_entries):
                self._display_password_details(self.password_entries[index])
    
    def _display_password_details(self, entry):
        """
        Display password details in the form.
        
        Args:
            entry (dict): Password entry to display
        """
        self.current_entry_id = entry["id"]
        
        # Set form values
        self.title_var.set(entry["title"])
        self.website_var.set(entry["website"] or "")
        self.username_var.set(entry["username"] or "")
        
        try:
            # Decrypt password with HMAC verification if enabled
            encrypted_password = entry["password_encrypted"]
            if self.user_manager.is_hmac_enabled() and self.user_manager.hmac_key:
                try:
                    decrypted_password = Encryption.decrypt_data(
                        encrypted_password, 
                        self.user_manager.encryption_key,
                        self.user_manager.hmac_key
                    )
                except ValueError as e:
                    # HMAC verification failed
                    messagebox.showerror(
                        "Security Alert", 
                        "HMAC verification failed: This password entry may have been tampered with."
                    )
                    # Try without HMAC as fallback
                    decrypted_password = Encryption.decrypt_data(
                        encrypted_password, 
                        self.user_manager.encryption_key
                    )
            else:
                # No HMAC, just decrypt
                decrypted_password = Encryption.decrypt_data(
                    encrypted_password, 
                    self.user_manager.encryption_key
                )
                
            self.password_var.set(decrypted_password)
            
            # Set notes
            self.notes_text.delete("1.0", tk.END)
            if entry["notes"]:
                self.notes_text.insert("1.0", entry["notes"])
            
            # Update password strength meter
            self._update_password_strength(decrypted_password)
            
        except Exception as e:
            messagebox.showerror(
                "Decryption Error", 
                f"Failed to decrypt password: {str(e)}"
            )
            self.password_var.set("")
            self.notes_text.delete("1.0", tk.END)
    
    def _clear_details_form(self):
        """Clear the password details form."""
        self.current_entry_id = None
        self.title_var.set("")
        self.website_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        self.notes_text.delete("1.0", tk.END)
        self.strength_meter.config(value=0)
        self.strength_label.config(text="")
    
    def _add_password(self):
        """Add a new password entry."""
        self._clear_details_form()
        self.title_var.set("New Password")
    
    def _save_password(self):
        """Save the current password entry."""
        if not self.user_manager.is_logged_in():
            return
        
        title = self.title_var.get()
        website = self.website_var.get()
        username = self.username_var.get()
        password = self.password_var.get()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        if not title or not password:
            messagebox.showerror("Error", "Title and password are required")
            return
        
        # Encrypt password with HMAC if enabled
        if self.user_manager.is_hmac_enabled() and self.user_manager.hmac_key:
            encrypted_password = Encryption.encrypt_data(
                password, 
                self.user_manager.encryption_key,
                self.user_manager.hmac_key
            )
        else:
            encrypted_password = Encryption.encrypt_data(
                password, 
                self.user_manager.encryption_key
            )
        
        user_id = self.user_manager.get_current_user()["id"]
        
        if self.current_entry_id:
            # Update existing entry
            success = self.database.update_password(
                self.current_entry_id, title, website, username, encrypted_password, notes)
            
            if success:
                messagebox.showinfo("Success", "Password updated successfully")
                self._load_passwords()
            else:
                messagebox.showerror("Error", "Failed to update password")
        else:
            # Add new entry
            entry_id = self.database.add_password(
                user_id, title, website, username, encrypted_password, notes)
            
            if entry_id:
                messagebox.showinfo("Success", "Password added successfully")
                self.current_entry_id = entry_id
                self._load_passwords()
            else:
                messagebox.showerror("Error", "Failed to add password")
    
    def _delete_password(self):
        """Delete the current password entry."""
        if not self.current_entry_id:
            messagebox.showerror("Error", "No password selected")
            return
        
        confirm = messagebox.askyesno(
            "Confirm Delete", 
            "Are you sure you want to delete this password?")
        
        if confirm:
            success = self.database.delete_password(self.current_entry_id)
            
            if success:
                messagebox.showinfo("Success", "Password deleted successfully")
                self._clear_details_form()
                self._load_passwords()
            else:
                messagebox.showerror("Error", "Failed to delete password")
    
    def _generate_password(self):
        """Generate a random password."""
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Password Length:").pack(pady=(20, 5), anchor="w", padx=20)
        
        length_frame = ttk.Frame(dialog)
        length_frame.pack(fill="x", padx=20)
        
        length_var = tk.IntVar(value=12)
        length_scale = ttk.Scale(
            length_frame, from_=8, to=32, variable=length_var, orient="horizontal")
        length_scale.pack(side=tk.LEFT, fill="x", expand=True)
        
        length_label = ttk.Label(length_frame, text="12")
        length_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        def update_length_label(event=None):
            length_label.config(text=str(length_var.get()))
        
        length_scale.bind("<Motion>", update_length_label)
        
        # Character set options
        ttk.Label(dialog, text="Include:").pack(pady=(10, 5), anchor="w", padx=20)
        
        uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Uppercase Letters (A-Z)", 
                       variable=uppercase_var).pack(anchor="w", padx=20)
        
        lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Lowercase Letters (a-z)", 
                       variable=lowercase_var).pack(anchor="w", padx=20)
        
        numbers_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Numbers (0-9)", 
                       variable=numbers_var).pack(anchor="w", padx=20)
        
        special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Special Characters (!@#$%^&*)", 
                       variable=special_var).pack(anchor="w", padx=20)
        
        # Generated password
        ttk.Label(dialog, text="Generated Password:").pack(pady=(10, 5), anchor="w", padx=20)
        
        password_frame = ttk.Frame(dialog)
        password_frame.pack(fill="x", padx=20)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=password_var, width=30)
        password_entry.pack(side=tk.LEFT, fill="x", expand=True)
        
        def generate():
            """Generate a password with the selected options."""
            length = length_var.get()
            uppercase = uppercase_var.get()
            lowercase = lowercase_var.get()
            numbers = numbers_var.get()
            special = special_var.get()
            
            # Ensure at least one character set is selected
            if not any([uppercase, lowercase, numbers, special]):
                messagebox.showerror("Error", "Select at least one character set")
                return
            
            password = PasswordUtils.generate_password(
                length, uppercase, lowercase, numbers, special)
            password_var.set(password)
        
        def use_password():
            """Use the generated password."""
            password = password_var.get()
            if password:
                self.password_var.set(password)
                self._update_password_strength(password)
                dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Button(button_frame, text="Generate", command=generate).pack(
            side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Use Password", command=use_password).pack(
            side=tk.LEFT)
        
        # Generate initial password
        generate()
    
    def _update_password_strength(self, password):
        """
        Update the password strength meter.
        
        Args:
            password (str): Password to check
        """
        score, strength, feedback = PasswordUtils.check_password_strength(password)
        
        # Update meter (score is 0-5, convert to 0-100)
        self.strength_meter.config(value=score * 20)
        
        # Update label
        self.strength_label.config(text=strength)
        
        # Set color based on strength
        if score <= 1:
            self.strength_meter.config(style="Red.Horizontal.TProgressbar")
        elif score <= 3:
            self.strength_meter.config(style="Yellow.Horizontal.TProgressbar")
        else:
            self.strength_meter.config(style="Green.Horizontal.TProgressbar")
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def _copy_to_clipboard(self, text):
        """
        Copy text to clipboard.
        
        Args:
            text (str): Text to copy
        """
        if text:
            pyperclip.copy(text)
            messagebox.showinfo("Copied", "Copied to clipboard")
    
    def _enable_hmac(self):
        """Enable HMAC verification for the current user."""
        if not self.user_manager.is_logged_in():
            return
            
        # If HMAC is already enabled, show a message
        if self.user_manager.is_hmac_enabled():
            messagebox.showinfo(
                "HMAC Verification", 
                "HMAC verification is already enabled for your account."
            )
            return
            
        # Ask for master password to confirm
        password = simpledialog.askstring(
            "Enable HMAC Verification", 
            "Enter your master password to enable HMAC verification:",
            show="•"
        )
        
        if not password:
            return
            
        # Enable HMAC
        if self.user_manager.enable_hmac(password):
            messagebox.showinfo(
                "HMAC Verification", 
                "HMAC verification has been enabled for your account.\n\n"
                "Your passwords are now protected against tampering."
            )
        else:
            messagebox.showerror(
                "Error", 
                "Failed to enable HMAC verification. Please check your master password."
            )
    
    def _disable_hmac(self):
        """Disable HMAC verification for the current user."""
        if not self.user_manager.is_logged_in():
            return
            
        # If HMAC is not enabled, show a message
        if not self.user_manager.is_hmac_enabled():
            messagebox.showinfo(
                "HMAC Verification", 
                "HMAC verification is not enabled for your account."
            )
            return
            
        # Confirm with the user
        confirm = messagebox.askyesno(
            "Disable HMAC Verification", 
            "Are you sure you want to disable HMAC verification?\n\n"
            "This will remove the protection against password tampering."
        )
        
        if not confirm:
            return
            
        # Ask for master password to confirm
        password = simpledialog.askstring(
            "Disable HMAC Verification", 
            "Enter your master password to disable HMAC verification:",
            show="•"
        )
        
        if not password:
            return
            
        # Disable HMAC
        if self.user_manager.disable_hmac(password):
            messagebox.showinfo(
                "HMAC Verification", 
                "HMAC verification has been disabled for your account."
            )
        else:
            messagebox.showerror(
                "Error", 
                "Failed to disable HMAC verification. Please check your master password."
            )
    
    def _show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About Secure Password Manager",
            "Secure Password Manager v1.1\n\n"
            "A secure application for managing your passwords with encryption.\n\n"
            "Features:\n"
            "- Secure password storage with encryption\n"
            "- HMAC verification to protect against tampering\n"
            "- Password generation\n"
            "- Password strength checking\n"
            "- Multiple user accounts\n\n"
            "© 2023 Secure Password Manager"
        )


def main():
    """Main entry point for the application."""
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()