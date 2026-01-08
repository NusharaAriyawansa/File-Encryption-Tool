# Secure File Encryption Tool
An Python application for encrypting and decrypting files with AES-256 encryption, secure key management, and integrity verification.

## Features
**AES-256-CBC Encryption** - Industry-standard encryption algorithm  
**PBKDF2 Key Derivation** - Strong password-based key generation with 100,000 iterations  
**HMAC-SHA256 Integrity** - Verify files haven't been tampered with  
**Secure Key Management** - Store keys securely with proper permissions  
**Two Key Types** - Random keys or password-derived keys  
**PKCS7 Padding** - Proper data padding for block cipher  
**Command-Line Interface** - Easy-to-use CLI for all operations  
**Cross-Platform** - Works on Windows, macOS, and Linux  

## Requirements
- Python 3.7 or higher
- PyCryptodome library

## Installation

  **Step 1: Install PyCryptodome**
    pip install pycryptodome

  **Step 2: Download the Tool**
    Save `encryption_tool.py` to your desired location

  **Step 3: Make it Executable (Linux/macOS)**
    chmod +x encryption_tool.py

  **Step 4: Generate a Key**
    Option A: Random key (recommended)
      python encryption_tool.py keygen -n mykey

    Option B: Password-based key
      python encryption_tool.py keygen -n mykey --password
  
  **Step 5: Encrypt a File**
    python encryption_tool.py encrypt -f document.pdf -k mykey
      This creates `document.pdf.enc` (encrypted and unreadable without the key).

  **Step 6: Decrypt a File**
    python encryption_tool.py decrypt -f document.pdf.enc -k mykey  
      This restores the original `document.pdf`.

  **Step 7: List Your Keys**
    python encryption_tool.py listkeys


