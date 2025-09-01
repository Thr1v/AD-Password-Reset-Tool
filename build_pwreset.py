# build_pwreset.py
# Script to build the AD Password Reset Tool executable

import subprocess
import os
import sys
from pathlib import Path

def check_requirements():
    """Check if all requirements are installed"""
    try:
        # Check for PyInstaller
        import PyInstaller
        print("PyInstaller is installed")
        
        # Check for other dependencies
        import tkinter
        import configparser
        print("All dependencies are installed")
        
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        
        # Try to install requirements
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                          check=True)
            print("Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to install dependencies")
            return False

def get_icon():
    """Create or check for icon file"""
    icon_path = Path("PWResetTool.ico")
    if not icon_path.exists():
        print("Icon file not found. Using default icon.")
        # You could create a default icon here
    else:
        print(f"Using icon from {icon_path}")
    return icon_path

def build_executable():
    """Build the executable using PyInstaller"""
    try:
        import PyInstaller.__main__
        
        icon_path = get_icon()
        
        # Configure PyInstaller arguments
        args = [
            'PWResetTool.py',
            '--name=ADPasswordReset',
            '--onefile',
            '--windowed',
            f'--icon={icon_path}' if icon_path.exists() else '',
        ]
        
        # Remove empty arguments
        args = [arg for arg in args if arg]
        
        # Run PyInstaller
        print("Building executable...")
        PyInstaller.__main__.run(args)
        
        print("\nBuild completed successfully!")
        print(f"Executable location: {Path.cwd() / 'dist' / 'ADPasswordReset.exe'}")
        return True
        
    except Exception as e:
        print(f"Error building executable: {e}")
        return False

def main():
    """Main function"""
    print("AD Password Reset Tool - Build Script")
    print("-" * 40)
    
    if not check_requirements():
        print("Please install required dependencies manually:")
        print("pip install -r requirements.txt")
        return
    
    build_executable()

if __name__ == "__main__":
    main()
