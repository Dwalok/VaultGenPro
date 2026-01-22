# VaultgenPro

Modern, lightweight CLI password manager built with Python. Uses a master password and strong encryption to keep your vault secure.

## Features
- Master password gate before access
- View, add, delete stored credentials
- Optional URL and notes per entry
- Built-in password generator with entropy estimate
- Encrypted local vault file (`vault.json`)

## Security model
- Key derivation: scrypt (N=2^15, r=8, p=1, length=32)
- Encryption: AES-GCM with unique salt and nonce per save
- If you lose the master password, the vault cannot be recovered

## Requirements
- Python 3.9+
- pip

## Installation

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux (bash)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

### Windows
```powershell
python vaultgen.py
```

### Linux
```bash
python3 vaultgen.py
```

## Usage
After launch, follow the menu:
- View passwords
- Add a password
- Delete a password
- Generate a password

## Vault file
- Stored in `vault.json` next to the script
- Do not commit this file to git
- Back it up if you want a safe offline copy

## Notes
This project is intended for local use. Review the code and security parameters if you plan to extend it.
