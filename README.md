# AD Password Reset Tool

A simple tool that allows apprentices to reset passwords in Active Directory without requiring full AD access.

## Features

- Search for users in Active Directory
- Reset user passwords according to company password policy (15+ characters with at least 1 number)
- Force users to change password at next logon
- Secure storage of administrative credentials

## Setup Instructions

### Prerequisites

- Windows system with Python 3.6+ installed
- Network connectivity to Active Directory server
- Administrative credentials with permission to reset passwords

### Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the tool:
   ```
   python PWResetTool.py
   ```

### Building the Executable

To create a standalone executable that can be distributed to apprentices:

1. Run the build script:
   ```
   python build_pwreset.py
   ```
2. The executable will be created in the `dist` folder

### Configuration

The first time you run the tool, you will be prompted to enter the following information:

- AD Server Name: The hostname or IP of your Active Directory server
- Domain Name: Your domain name (e.g., CONTOSO)
- Admin Username: An administrative account with permission to reset passwords
- Admin Password: The password for the administrative account

This information is stored in a configuration file located at:
```
C:\Users\<YourUsername>\pwresettool.ini
```

**Note**: The password is stored using simple base64 encoding. For production use, consider implementing a more secure storage method like Windows DPAPI.

## How It Works

The tool works by:

1. Using PowerShell commands to interact with Active Directory
2. Searching AD using the provided administrative credentials
3. Resetting passwords using the Set-ADAccountPassword cmdlet
4. Setting the "Change password at next logon" flag for the user

When deployed on a computer without the Active Directory module, the tool will establish a remote PowerShell session to the AD server to perform operations.

## Deployment Options

### Option 1: Standalone Executable

Build and distribute the executable to apprentice machines. They won't need Python installed.

### Option 2: Run from Network Share

Place the tool on a network share and have apprentices run it from there. This makes updates easier to manage.

### Option 3: Remote Desktop to Server

Install the tool on a server with the AD module and have apprentices access it through Remote Desktop.

## Security Considerations

- The tool uses a service account with limited permissions for AD operations
- All password resets are logged for auditing
- User searches are limited to prevent information disclosure
- Passwords must meet company policy requirements

## Troubleshooting

If you encounter issues:

1. Check network connectivity to the AD server
2. Verify the service account has appropriate permissions
3. Ensure the AD PowerShell module is accessible
4. Check the configuration file for correct settings
