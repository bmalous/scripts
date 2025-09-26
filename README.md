Here's how to set up this hash comparison script as a Thunar custom action:
Step 1: Install the Script
First, save the script and make it executable:
bash
# Save to a system location
sudo cp mini_clip_hash.sh /usr/local/bin/mini_clip_hash
sudo chmod +x /usr/local/bin/mini_clip_hash

# Or save to your personal bin directory
mkdir -p ~/.local/bin
cp hash_compare.sh ~/.local/bin/mini_clip_hash
chmod +x ~/.local/bin/mini_clip_hash
Step 2: Create Thunar Custom Action
1.	Open Thunar and go to Edit → Configure custom actions (or press Ctrl+Shift+C)
2.	Click the "+" button to create a new custom action
3.	Fill in the Basic tab: 
o	Name: Compare Hash with Clipboard
o	Description: Compare file hash against clipboard hash
o	Command: /usr/local/bin/mini_clip_hash %F 
	(Use ~/.local/bin/mini_clip_hash %F if you installed it locally)
o	Icon: Choose an appropriate icon (optional)
4.	Configure the Appearance Conditions tab: 
o	File Pattern: * (to match all files)
o	Appears if selection contains: Select "Regular Files"
o	Other File Types: Uncheck all boxes
o	Directories: Uncheck
o	Audio Files, Image Files, etc.: Check the types you want or leave all checked
Step 3: Test the Setup
1.	Copy a hash to clipboard (e.g., from a website or terminal)
2.	Right-click on a file in Thunar
3.	Select "Compare Hash with Clipboard" from the context menu
4.	View the result in the Zenity dialog
Alternative Command Variations
If you want multiple hash comparison options, you can create several custom actions:
For multiple files:
•	Command: /usr/local/bin/mini_clip_hash %F
•	Description: Compare multiple files with clipboard hash
For single file with terminal output:
•	Command: gnome-terminal -e "/usr/local/bin/mini_clip_hash '%f'"
•	Description: Compare hash in terminal
Troubleshooting
If the custom action doesn't appear:
•	Ensure the script has execute permissions
•	Check that the path in the command is correct
•	Verify Thunar is restarted after creating the action
If you get "command not found":
•	Use the full path to the script
•	Make sure ~/.local/bin is in your PATH if using that location
Dependencies check:
bash
# Make sure you have the required tools
which zenity xsel xclip md5sum sha256sum
Usage Workflow
1.	Find a file's expected hash (from a website, README, etc.)
2.	Copy that hash to your clipboard
3.	Right-click the downloaded file in Thunar
4.	Select "Compare Hash with Clipboard"
5.	Get instant verification via the popup dialog
This creates a seamless file integrity verification workflow directly from your file manager!
