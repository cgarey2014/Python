<p align="center">
  <img src="https://github.com/cgarey2014/Python/blob/main/shell_notes/assets/shell_notes.png" alt="Shell Notes Banner" width="600">
</p>

# Shell Notes

**Shell Notes** is a user-friendly terminal logging utility that gives you a clean, interactive interface to drop into shell sessions with full input/output logging. Whether you're auditing commands, studying terminal workflows, or keeping track of what you ran, **Shell Notes** makes logging simple and organized.

---

## 🧰 Features

- 🖥️ Fully interactive shell environment with session logging
- 📂 Timestamped log files organized and easy to access
- 🔍 Review logs with a searchable, numbered menu system
- 🗑️ Option to delete unwanted logs right from the interface
- 🧼 Clean interface with screen clearing between menus
- ⚙️ Ready on boot, waits silently until invoked

---

## 🚀 Getting Started

### Prerequisites

- Python 3.6 or higher
- Bash/Zsh shell (Linux)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/shell-notes.git
cd shell-notes
```

2. Make it executable

```bash
chmod +x shell_notes.py
```

3. Move it to your scripts folder (optional):
```bash
sudo mkdir ~/scripts/
mv shell_notes.py ~/scripts/
```

4. Add this line to your .bashrc, .zshrc, or appropriate shell config file:

```bash
alias shellnotes='python3 ~/scripts/shell_notes.py'
```
This ensures Shell Notes runs at boot but remains idle until you type a command.

🧭 Usage
After logging in or launching a new terminal session, you’ll see:

```bash
Welcome to Shell Notes.
Type 'shell' to drop into a shell session.
Type 'logs' to list and view previous logs.
Type 'exit' to quit.
```
shell – Launch a normal shell session, logging input/output to a timestamped file.

logs – List available logs and choose to view or delete them.

exit – Quit Shell Notes.

📂 Log Storage
All logs are stored in:

```bash
~/terminal_logs/
```

Each session is saved as:

```bash
LogFile_YYYY-MM-DD_HH-MM-SS.log
```

💡 Sample Interaction
```bash
>>> logs

[1] LogFile_2025-04-21_08-12-26.log
[2] LogFile_2025-04-21_09-43-10.log

Select log to view or type 'd' to delete one:
```

🛠️ Contributing
Contributions are welcome! Open an issue or pull request to improve functionality, fix bugs, or add new features.

📝 License
This project is licensed under the MIT License. See the LICENSE file for more information.

🙏 Acknowledgements
Thanks to the open source community for inspiring tools that enhance terminal workflows.
