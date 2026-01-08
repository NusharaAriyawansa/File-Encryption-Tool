#!/usr/bin/env python3
"""
Secure File Encryption Tool
An encryption application with AES-256, key management,password-based encryption, and integrity verification.

Author: Nushara Ariyawansa
"""

import os
import sys
import json
import hashlib
import argparse
from pathlib import Path
from getpass import getpass
from datetime import datetime

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import HMAC, SHA256
except ImportError:
    print("ERROR: PyCryptodome not installed!")
    print("Install it with: pip install pycryptodome --break-system-packages")
    sys.exit(1)


class EncryptionTool:
    """Handles all encryption, decryption, and key management operations."""
    
    # Constants
    AES_KEY_SIZE = 32  # 256-bit key
    IV_SIZE = 16      # 128-bit IV
    PBKDF2_ITERATIONS = 100000
    SALT_SIZE = 16
    TAG_SIZE = 32     # HMAC tag size
    
    # File header to identify encrypted files
    FILE_HEADER = b"SECUREFILE_v1"
    
    def __init__(self):
        """Initialize the encryption tool."""
        self.keys_dir = Path.home() / ".encryption_keys"
        self.keys_dir.mkdir(exist_ok=True, mode=0o700)
    
    # ==================== Key Management ====================
    
    def generate_key(self, key_name: str, use_password: bool = False) -> dict:
        """
        Generate a new encryption key.
        
        Args:
            key_name: Name to save the key as
            use_password: If True, derive key from password instead of random
            
        Returns:
            Dictionary with key information
        """
        if use_password:
            password = getpass("Enter password for key derivation: ")
            confirm = getpass("Confirm password: ")
            
            if password != confirm:
                raise ValueError("Passwords do not match!")
            
            key_info = self._derive_key_from_password(password, key_name)
        else:
            salt = get_random_bytes(self.SALT_SIZE)
            key = get_random_bytes(self.AES_KEY_SIZE)
            key_info = {
                "name": key_name,
                "key": key.hex(),
                "salt": salt.hex(),
                "created": datetime.now().isoformat(),
                "method": "random"
            }
        
        # Save key securely
        self._save_key(key_name, key_info)
        print(f"✓ Key '{key_name}' generated and saved successfully")
        return key_info
    
    def _derive_key_from_password(self, password: str, key_name: str) -> dict:
        """Derive a key from a password using PBKDF2."""
        salt = get_random_bytes(self.SALT_SIZE)
        key = PBKDF2(
            password,
            salt,
            self.AES_KEY_SIZE,
            count=self.PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )
        return {
            "name": key_name,
            "key": key.hex(),
            "salt": salt.hex(),
            "created": datetime.now().isoformat(),
            "method": "password"
        }
    
    def _save_key(self, key_name: str, key_info: dict) -> None:
        """Save key information to file."""
        key_path = self.keys_dir / f"{key_name}.json"
        
        # Warn if file exists
        if key_path.exists():
            response = input(f"Key '{key_name}' already exists. Overwrite? (y/N): ")
            if response.lower() != 'y':
                raise ValueError("Operation cancelled")
        
        with open(key_path, 'w') as f:
            json.dump(key_info, f, indent=2)
        
        # Set secure permissions
        key_path.chmod(0o600)
    
    def load_key(self, key_name: str) -> bytes:
        """
        Load a key from storage.
        
        Args:
            key_name: Name of the key to load
            
        Returns:
            The decryption key as bytes
        """
        key_path = self.keys_dir / f"{key_name}.json"
        
        if not key_path.exists():
            raise FileNotFoundError(f"Key '{key_name}' not found in {self.keys_dir}")
        
        with open(key_path, 'r') as f:
            key_info = json.load(f)
        
        if key_info["method"] == "password":
            password = getpass(f"Enter password for key '{key_name}': ")
            salt = bytes.fromhex(key_info["salt"])
            key = PBKDF2(
                password,
                salt,
                self.AES_KEY_SIZE,
                count=self.PBKDF2_ITERATIONS,
                hmac_hash_module=SHA256
            )
        else:
            key = bytes.fromhex(key_info["key"])
        
        return key
    
    def list_keys(self) -> list:
        """List all available keys."""
        keys = []
        for key_file in self.keys_dir.glob("*.json"):
            with open(key_file, 'r') as f:
                key_info = json.load(f)
            keys.append({
                "name": key_info["name"],
                "method": key_info["method"],
                "created": key_info["created"]
            })
        return keys
    
    # ==================== Encryption ====================
    
    def encrypt_file(self, file_path: str, key_name: str, output_path: str = None) -> str:
        """
        Encrypt a file.
        
        Args:
            file_path: Path to the file to encrypt
            key_name: Name of the key to use
            output_path: Optional output path (default: original_file.enc)
            
        Returns:
            Path to the encrypted file
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File '{file_path}' not found")
        
        # Load encryption key
        key = self.load_key(key_name)
        
        # Generate IV and salt
        iv = get_random_bytes(self.IV_SIZE)
        
        # Read file content
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Add PKCS7 padding
        padding_length = AES.block_size - (len(plaintext) % AES.block_size)
        plaintext_padded = plaintext + bytes([padding_length] * padding_length)
        
        ciphertext = cipher.encrypt(plaintext_padded)
        
        # Generate HMAC for integrity
        h = HMAC.new(key, digestmod=SHA256)
        h.update(iv + ciphertext)
        tag = h.digest()
        
        # Create encrypted file
        if output_path is None:
            output_path = f"{file_path}.enc"
        
        output_path = Path(output_path)
        
        with open(output_path, 'wb') as f:
            f.write(self.FILE_HEADER)
            f.write(iv)
            f.write(tag)
            f.write(ciphertext)
        
        # Secure permissions
        output_path.chmod(0o600)
        
        file_size = len(plaintext)
        print(f"✓ File encrypted successfully: {output_path}")
        print(f"  Original size: {file_size:,} bytes")
        print(f"  Encrypted size: {output_path.stat().st_size:,} bytes")
        
        return str(output_path)
    
    # ==================== Decryption ====================
    
    def decrypt_file(self, file_path: str, key_name: str, output_path: str = None) -> str:
        """
        Decrypt a file.
        
        Args:
            file_path: Path to the encrypted file
            key_name: Name of the key to use
            output_path: Optional output path (default: removes .enc extension)
            
        Returns:
            Path to the decrypted file
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File '{file_path}' not found")
        
        # Read encrypted file
        with open(file_path, 'rb') as f:
            file_header = f.read(len(self.FILE_HEADER))
            iv = f.read(self.IV_SIZE)
            tag = f.read(self.TAG_SIZE)
            ciphertext = f.read()
        
        # Verify file header
        if file_header != self.FILE_HEADER:
            raise ValueError("Invalid encrypted file format")
        
        # Load decryption key
        key = self.load_key(key_name)
        
        # Verify HMAC
        h = HMAC.new(key, digestmod=SHA256)
        h.update(iv + ciphertext)
        
        try:
            h.verify(tag)
        except ValueError:
            raise ValueError("File integrity check failed! File may be corrupted or tampered with.")
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        padding_length = plaintext_padded[-1]
        plaintext = plaintext_padded[:-padding_length]
        
        # Save decrypted file
        if output_path is None:
            if str(file_path).endswith('.enc'):
                output_path = str(file_path)[:-4]
            else:
                output_path = f"{file_path}.dec"
        
        output_path = Path(output_path)
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        # Secure permissions
        output_path.chmod(0o600)
        
        print(f"✓ File decrypted successfully: {output_path}")
        print(f"  Decrypted size: {len(plaintext):,} bytes")
        
        return str(output_path)


# ==================== CLI Interface ====================

def main():
    """Command-line interface for the encryption tool."""
    parser = argparse.ArgumentParser(
        description="Secure File Encryption Tool - Encrypt and decrypt files with AES-256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a random key
  python encryption_tool.py keygen -n mykey
  
  # Generate a password-based key
  python encryption_tool.py keygen -n mykey --password
  
  # List all keys
  python encryption_tool.py listkeys
  
  # Encrypt a file
  python encryption_tool.py encrypt -f document.pdf -k mykey
  
  # Decrypt a file
  python encryption_tool.py decrypt -f document.pdf.enc -k mykey
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate key command
    keygen_parser = subparsers.add_parser('keygen', help='Generate a new encryption key')
    keygen_parser.add_argument('-n', '--name', required=True, help='Name for the key')
    keygen_parser.add_argument('--password', action='store_true',
                              help='Derive key from password instead of random')
    
    # List keys command
    subparsers.add_parser('listkeys', help='List all available keys')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('-f', '--file', required=True, help='File to encrypt')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Key name to use')
    encrypt_parser.add_argument('-o', '--output', help='Output file path (optional)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('-f', '--file', required=True, help='File to decrypt')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Key name to use')
    decrypt_parser.add_argument('-o', '--output', help='Output file path (optional)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    tool = EncryptionTool()
    
    try:
        if args.command == 'keygen':
            tool.generate_key(args.name, use_password=args.password)
        
        elif args.command == 'listkeys':
            keys = tool.list_keys()
            if not keys:
                print("No keys found.")
            else:
                print(f"\n{'Key Name':<20} {'Method':<15} {'Created':<20}")
                print("-" * 55)
                for key in keys:
                    print(f"{key['name']:<20} {key['method']:<15} {key['created']:<20}")
                print()
        
        elif args.command == 'encrypt':
            tool.encrypt_file(args.file, args.key, args.output)
        
        elif args.command == 'decrypt':
            tool.decrypt_file(args.file, args.key, args.output)
    
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
