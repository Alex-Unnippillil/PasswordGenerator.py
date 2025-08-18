# Password Generator

A GUI application for creating secure passwords.

## Requirements

- Python 3.6+
- `tkinter` (usually included with Python; on Linux install `python3-tk`)
- `pyperclip` for clipboard operations

### Platform Notes

- **Linux:** Requires an X server or graphical environment for `tkinter`.
- **Windows/macOS:** `tkinter` is typically bundled with standard Python installations.

## Installation

1. Install Python 3.6 or later.
2. Install dependencies:
   ```bash
   pip install pyperclip
   ```
   On Linux, you may also need:
   ```bash
   sudo apt-get install python3-tk
   ```

## Running

```bash
python passwordGenerator.py
```

## Usage

- Set the password length and choose character sets (lowercase, uppercase, digits, special characters).
- Click **Generate Password** or press `Ctrl+G` to create a password.
- Press `Ctrl+C` to copy the latest password to the clipboard.
- Press `Ctrl+S` to save the password history to a file.
- Enable **Auto-copy** to copy passwords automatically.
- The password strength meter provides feedback, and the history panel lets you reuse previous passwords.
