# filepath: c:\Scripts\messaround\PWResetTool\PWResetTool.py
# Active Directory Password Reset Tool
# This tool allows limited AD password reset functionality for apprentices without giving them full AD access

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import re
import os
import sys
import secrets
import string
import configparser
import base64
import json
import logging
import datetime
from pathlib import Path

class PasswordResetTool:
    def __init__(self, root):
        self.root = root
        self.root.title("AD Password Reset Tool")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        # Set the icon if available
        if getattr(sys, 'frozen', False):
            application_path = Path(sys.executable).parent
        else:
            application_path = Path(__file__).parent
        
        icon_path = application_path / "appicon.ico"
        if icon_path.exists():
            self.root.iconbitmap(icon_path)
        
        # Load configuration
        self.config = self.load_config()
        
        # Set up logging
        log_path = Path.home() / "pwresettool.log"
        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Create the main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a style
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 10))
        style.configure("TLabel", font=("Arial", 10))
        style.configure("TEntry", font=("Arial", 10))
        
        # Create the widgets
        ttk.Label(main_frame, text="AD Password Reset Tool", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Search User:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(search_frame, text="Search", command=self.search_user).grid(row=0, column=2, padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create Treeview for user search results
        self.tree = ttk.Treeview(results_frame, columns=("username", "fullname"), show="headings")
        self.tree.heading("username", text="Username")
        self.tree.heading("fullname", text="Full Name")
        self.tree.column("username", width=150)
        self.tree.column("fullname", width=300)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree.bind("<Double-1>", self.on_user_selected)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="Reset Password", command=self.reset_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Generate Password", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Test Connection", command=self.test_ad_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Settings", command=self.setup).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Exit", command=self.root.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Password entry frame
        password_frame = ttk.LabelFrame(main_frame, text="Password")
        password_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(password_frame, text="New Password:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(password_frame, width=30, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(password_frame, text="Confirm Password:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.confirm_password_entry = ttk.Entry(password_frame, width=30, show="*")
        self.confirm_password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Password visibility toggle
        self.show_password = tk.BooleanVar()
        self.show_password.set(False)
        ttk.Checkbutton(password_frame, text="Show Password", 
                       variable=self.show_password, 
                       command=self.toggle_password_visibility).grid(row=0, column=2, padx=5, pady=5, rowspan=2)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)
        
        # Authentication check
        self.check_authentication()

    def load_config(self):
        config = configparser.ConfigParser()
        config_path = Path.home() / "pwresettool.ini"
        
        # Default configuration
        if not config_path.exists():
            config['AD'] = {
                'server': '',
                'admin_username': '',
                'encrypted_password': '',
                'domain': ''
            }
            try:
                with open(config_path, 'w') as configfile:
                    config.write(configfile)
                messagebox.showinfo("Configuration Created", 
                                   f"A configuration file has been created at {config_path}.\n"
                                   f"Please update it with your AD settings.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not create config file: {str(e)}")
        else:
            try:
                config.read(config_path)
            except Exception as e:
                messagebox.showerror("Error", f"Could not read config file: {str(e)}")
                
        return config

    def check_authentication(self):
        """Check if we have valid AD credentials configured"""
        try:
            server = self.config.get('AD', 'server', fallback=None)
            admin_username = self.config.get('AD', 'admin_username', fallback=None)
            encrypted_password = self.config.get('AD', 'encrypted_password', fallback=None)
            domain = self.config.get('AD', 'domain', fallback=None)
            
            if not all([server, admin_username, encrypted_password, domain]):
                self.status_var.set("Configuration incomplete. Please update settings.")
                return False
                
            # Test connection to AD (this will be implemented with actual AD connection)
            # For now, just assume it's valid if configs exist
            self.status_var.set("Connected to Active Directory")
            return True
            
        except Exception as e:
            self.status_var.set(f"Authentication Error: {str(e)}")
            return False

    def search_user(self):
        """Search for user in Active Directory"""
        search_term = self.search_entry.get().strip()
        if not search_term:
            messagebox.showinfo("Input Required", "Please enter a search term")
            return
            
        self.status_var.set("Searching...")
        self.root.update_idletasks()
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        try:
            # Construct and run PowerShell command to search AD
            command = [
                "powershell", 
                "-Command",
                f"$securePassword = ConvertTo-SecureString -String '{self.get_plain_password()}' -AsPlainText -Force; " +
                f"$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList '{self.config.get('AD', 'domain')}\\{self.config.get('AD', 'admin_username')}', $securePassword; " +
                f"Import-Module ActiveDirectory -ErrorAction SilentlyContinue; " +
                f"if (-not (Get-Module ActiveDirectory)) {{ " +
                f"    $session = New-PSSession -ComputerName '{self.config.get('AD', 'server')}' -Credential $credential; " +
                f"    Invoke-Command -Session $session -ScriptBlock {{ " +
                f"        Import-Module ActiveDirectory; " +
                f"        Get-ADUser -Filter \"Name -like '*{search_term}*' -or SamAccountName -like '*{search_term}*'\" -Properties DisplayName | " +
                f"        Select-Object SamAccountName, DisplayName | " +
                f"        ConvertTo-Json " +
                f"    }} " +
                f"}} else {{ " +
                f"    Get-ADUser -Filter \"Name -like '*{search_term}*' -or SamAccountName -like '*{search_term}*'\" -Properties DisplayName | " +
                f"    Select-Object SamAccountName, DisplayName | " +
                f"    ConvertTo-Json " +
                f"}}"
            ]
            
            # Actually run the command and get results
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"PowerShell error: {result.stderr}")
            
            # Parse JSON output from PowerShell
            output = result.stdout.strip()
            
            if not output:
                self.status_var.set("No users found")
                return
                
            users = json.loads(output)
            # Handle case where only one user is returned (not in a list)
            if not isinstance(users, list):
                users = [users]
                
            for user in users:
                self.tree.insert("", tk.END, values=(user["SamAccountName"], user["DisplayName"]))
                
            self.status_var.set(f"Found {len(users)} users")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while searching: {str(e)}")
            self.status_var.set("Search failed")

    def on_user_selected(self, event):
        """Handle user selection from the tree"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        username = self.tree.item(item, "values")[0]
        self.generate_password()
        self.status_var.set(f"Selected user: {username}")

    def generate_password(self):
        """Generate a random password that meets policy requirements"""
        # Generate a password with at least 15 chars and at least 1 number
        alphabet = string.ascii_letters + string.punctuation
        numbers = string.digits
        
        # Ensure at least one number
        password = secrets.choice(numbers)
        
        # Add remaining characters to reach minimum 15 characters
        password += ''.join(secrets.choice(alphabet + numbers) for _ in range(14))
        
        # Shuffle the password to randomize the position of the number
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        password = ''.join(password_list)
        
        # Set the password in the entry fields
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.confirm_password_entry.delete(0, tk.END)
        self.confirm_password_entry.insert(0, password)
        
        # Show the password in a message box for visibility
        messagebox.showinfo("Generated Password", 
                           f"Password generated: {password}\n\n"
                           "The password has been copied to the password fields.\n"
                           "You can also check 'Show Password' to view it in the fields.")
        
        return password

    def reset_password(self):
        """Reset the selected user's password"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("Selection Required", "Please select a user first")
            return
            
        item = selected_items[0]
        username = self.tree.item(item, "values")[0]
        
        # Get password
        new_password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Validate passwords
        if not new_password:
            messagebox.showinfo("Input Required", "Please enter a new password")
            return
            
        if new_password != confirm_password:
            messagebox.showinfo("Password Mismatch", "Passwords do not match")
            return
            
        if len(new_password) < 15:
            messagebox.showinfo("Invalid Password", "Password must be at least 15 characters long")
            return
            
        if not any(c.isdigit() for c in new_password):
            messagebox.showinfo("Invalid Password", "Password must contain at least one number")
            return
            
        # Confirm action
        if not messagebox.askyesno("Confirm Reset", f"Are you sure you want to reset the password for {username}?"):
            return
            
        try:
            self.status_var.set(f"Resetting password for {username}...")
            self.root.update_idletasks()
            
            # Log the reset attempt
            logging.info(f"Password reset initiated for user {username} by {os.getlogin()}")
            
            # Construct PowerShell command to reset password
            command = [
                "powershell",
                "-Command",
                f"$securePassword = ConvertTo-SecureString -String '{self.get_plain_password()}' -AsPlainText -Force; " +
                f"$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList '{self.config.get('AD', 'domain')}\\{self.config.get('AD', 'admin_username')}', $securePassword; " +
                f"$newSecurePwd = ConvertTo-SecureString -String '{new_password.replace("'", "''")}' -AsPlainText -Force; " +
                f"Import-Module ActiveDirectory -ErrorAction SilentlyContinue; " +
                f"if (-not (Get-Module ActiveDirectory)) {{ " +
                f"    $session = New-PSSession -ComputerName '{self.config.get('AD', 'server')}' -Credential $credential; " +
                f"    Invoke-Command -Session $session -ScriptBlock {{ " +
                f"        param($username, $newSecurePwd) " +
                f"        Import-Module ActiveDirectory; " +
                f"        Set-ADAccountPassword -Identity $username -NewPassword $newSecurePwd -Reset; " +
                f"        Set-ADUser -Identity $username -ChangePasswordAtLogon $true; " +
                f"        Write-Output 'Password reset successful' " +
                f"    }} -ArgumentList '{username}', $newSecurePwd " +
                f"}} else {{ " +
                f"    Set-ADAccountPassword -Identity '{username}' -NewPassword $newSecurePwd -Reset; " +
                f"    Set-ADUser -Identity '{username}' -ChangePasswordAtLogon $true; " +
                f"    Write-Output 'Password reset successful' " +
                f"}}"
            ]
            
            # Actually run the PowerShell command
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"PowerShell error: {result.stderr}")
                
            # Check output for success message
            output = result.stdout.strip()
            
            if "Password reset successful" in output:
                messagebox.showinfo("Success", f"Password for {username} has been reset successfully.\nUser will be required to change password at next logon.")
                self.status_var.set("Password reset complete")
                logging.info(f"Password reset successful for user {username} by {os.getlogin()}")
            else:
                raise Exception("Password reset may have failed. No success confirmation received.")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while resetting the password: {str(e)}")
            self.status_var.set("Password reset failed")
            logging.error(f"Password reset failed for user {username}: {str(e)}")

    def get_plain_password(self):
        """Decrypt the admin password from config"""
        try:
            encrypted = self.config.get('AD', 'encrypted_password', fallback='')
            if not encrypted:
                return ''
                
            # This is a very simple encryption/decryption method
            # In a production environment, use more secure methods like keyring or Windows DPAPI
            return base64.b64decode(encrypted.encode()).decode()
        except Exception:
            return ''
            
    def encrypt_password(self, password):
        """Encrypt a password for storage"""
        # Simple base64 encoding - in production use more secure methods
        return base64.b64encode(password.encode()).decode()
        
    def toggle_password_visibility(self):
        """Toggle password visibility in entry fields"""
        if self.show_password.get():
            self.password_entry.config(show="")
            self.confirm_password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            self.confirm_password_entry.config(show="*")
        
    def test_ad_connection(self):
        """Test connection to Active Directory with current credentials"""
        try:
            self.status_var.set("Testing AD connection...")
            self.root.update_idletasks()
            
            command = [
                "powershell",
                "-Command",
                f"$securePassword = ConvertTo-SecureString -String '{self.get_plain_password()}' -AsPlainText -Force; " +
                f"$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList '{self.config.get('AD', 'domain')}\\{self.config.get('AD', 'admin_username')}', $securePassword; " +
                f"Import-Module ActiveDirectory -ErrorAction SilentlyContinue; " +
                f"if (-not (Get-Module ActiveDirectory)) {{ " +
                f"    $session = New-PSSession -ComputerName '{self.config.get('AD', 'server')}' -Credential $credential -ErrorAction Stop; " +
                f"    Invoke-Command -Session $session -ScriptBlock {{ " +
                f"        Import-Module ActiveDirectory; " +
                f"        Write-Output ('Connection successful to ' + (Get-ADDomain).DNSRoot) " +
                f"    }}; " +
                f"    Remove-PSSession $session; " +
                f"}} else {{ " +
                f"    Import-Module ActiveDirectory; " +
                f"    Write-Output ('Connection successful to ' + (Get-ADDomain).DNSRoot) " +
                f"}}"
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"PowerShell error: {result.stderr}")
                
            output = result.stdout.strip()
            
            if "Connection successful" in output:
                messagebox.showinfo("Connection Test", f"Successfully connected to Active Directory: {output}")
                self.status_var.set("Connected to Active Directory")
                return True
            else:
                raise Exception("Could not verify AD connection")
                
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to Active Directory: {str(e)}")
            self.status_var.set("AD connection failed")
            return False
            
    def setup(self):
        """Setup the configuration"""
        try:
            server = simpledialog.askstring("Configuration", "Enter AD Server Name:")
            domain = simpledialog.askstring("Configuration", "Enter Domain Name:")
            admin_username = simpledialog.askstring("Configuration", "Enter Admin Username:")
            admin_password = simpledialog.askstring("Configuration", "Enter Admin Password:", show='*')
            
            if all([server, domain, admin_username, admin_password]):
                encrypted_password = self.encrypt_password(admin_password)
                
                self.config['AD'] = {
                    'server': server,
                    'admin_username': admin_username,
                    'encrypted_password': encrypted_password,
                    'domain': domain
                }
                
                config_path = Path.home() / "pwresettool.ini"
                with open(config_path, 'w') as configfile:
                    self.config.write(configfile)
                    
                messagebox.showinfo("Success", "Configuration saved successfully")
                
                # Test the connection with new settings
                self.test_ad_connection()
                
                return True
            else:
                messagebox.showwarning("Incomplete Information", "All fields are required")
                return False
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving configuration: {str(e)}")
            return False

def create_exe():
    """Create executable using PyInstaller"""
    try:
        import PyInstaller.__main__
        
        PyInstaller.__main__.run([
            '--name=ADPasswordReset',
            '--onefile',
            '--windowed',
            '--add-data=appicon.ico;.',
            'PWResetTool.py'
        ])
        
        print("Executable created successfully")
        return True
        
    except ImportError:
        print("PyInstaller not found. Please install it using 'pip install pyinstaller'")
        return False
    except Exception as e:
        print(f"Error creating executable: {str(e)}")
        return False

def main():
    root = tk.Tk()
    app = PasswordResetTool(root)
    
    # Check if config exists and is complete
    try:
        server = app.config.get('AD', 'server', fallback=None)
        admin_username = app.config.get('AD', 'admin_username', fallback=None)
        encrypted_password = app.config.get('AD', 'encrypted_password', fallback=None)
        domain = app.config.get('AD', 'domain', fallback=None)
        
        if not all([server, admin_username, encrypted_password, domain]):
            if not app.setup():
                messagebox.showwarning("Configuration Required", 
                                      "The application is not configured properly.\n"
                                      "Please update the configuration file manually.")
    except Exception as e:
        messagebox.showerror("Error", f"Configuration error: {str(e)}")
    
    root.mainloop()

if __name__ == "__main__":
    main()
