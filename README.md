Script compares hash from clipboard against file hash for MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, BLAKE2b, BLAKE2s, BLAKE3, WHIRLPOOL, RIPEMD, XXHash, CRC32, and Adler32 with Zenity dialogs

What the Script Does
The script compares hash values from your clipboard against files you select in Thunar.

It extracts a hash from your clipboard (supports both Wayland and X11)
Calculates multiple hash types for selected files using various algorithms:

Common hashes: MD5, SHA1, SHA256, SHA512, etc.
Advanced hashes: BLAKE2b/s, BLAKE3, SHA3 variants
Legacy hashes: CRC32, Adler32, WHIRLPOOL, RIPEMD160
Fast hashes: XXHash


Compares and reports matches via GUI dialog or terminal output
Shows results indicating which files match the clipboard hash and which algorithm was used

How to Set Up in Thunar Custom Actions

Open Thunar and go to Edit → Configure custom actions
Click "+" to add a new action with these settings:
Basic tab:

Name: Hash Compare
Description: Compare file hashes with clipboard content
Command: /path/to/your/script.sh %F

Replace /path/to/your/script.sh with the actual path to your saved script
%F passes all selected files to the script



Appearance Conditions tab:

Check "Appears if selection contains:" → "Other Files"
This makes the action available when you select files


Save the action

How to Use

Copy a hash value to your clipboard (from a website, terminal, etc.)
Select one or more files in Thunar that you want to verify
Right-click and choose "Hash Compare" from the context menu
View the results in a popup dialog showing which files matched and which hash algorithm was detected

Requirements
The script needs:

python3 (required)
A clipboard utility: wl-paste (Wayland) or xclip/xsel (X11)
zenity for GUI dialogs (optional - falls back to terminal output)
Optional tools for additional hash types: b3sum, openssl, xxhsum

This is particularly useful for verifying downloaded files against published checksums - just copy the checksum, select the file(s), and run the action to instantly verify integrity.
