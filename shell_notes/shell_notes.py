import os
import subprocess
import time
import datetime
import logging

# Define clear screen function
def clear_screen():
    os.system('clear')  # or 'cls' for Windows

# Logging configuration
log_dir = "/home/cosmo/terminal_logs"  # Directory for logs
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

def create_log_file():
    """Creates a log file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(log_dir, f"LogFile_{timestamp}.log")
    return log_file

def start_shell(log_file):
    """Drop into the shell and log input/output."""
    # This starts a shell (user default shell) and logs its input and output
    # Using `tee` to capture output and redirect both stdout and stderr to the log file

    # Start a new shell session (bash/zsh)
    command = f"tee -a {log_file}"  # `tee` will append the shell output to the log file
    
    # Open the log file and write logs
    with open(log_file, 'w') as file:
        file.write(f"[+] Shell session started at {datetime.datetime.now()}\n")
        
        # Start a subprocess that will run the shell and pipe all output/input through tee
        subprocess.call(f"bash | tee -a {log_file}", shell=True)

def view_logs():
    """List and view log files."""
    log_files = [f for f in os.listdir(log_dir) if f.startswith("LogFile_")]
    
    if not log_files:
        print("\033[91mNo log files found.\033[0m")  # Red message for no logs
        return
    
    # Display log files
    print("\033[94mAvailable Log Files:\033[0m")
    for i, filename in enumerate(log_files, 1):
        print(f"\033[92m{i}. {filename}\033[0m")  # Green numbered log files
    
    # Ask for log selection
    try:
        selection = int(input("\n\033[93mEnter the number of the log to view (0 to cancel): \033[0m"))
        if selection == 0:
            print("\033[91mCancelled log selection.\033[0m")
            return
        if selection < 1 or selection > len(log_files):
            print("\033[91mInvalid selection. Please choose a valid log number.\033[0m")
            return

        selected_log = log_files[selection - 1]
        log_file_path = os.path.join(log_dir, selected_log)

        # Displaying the selected log file
        with open(log_file_path, "r") as file:
            print("\033[94m" + "-"*60 + "\033[0m")
            print(file.read())
            print("\033[94m" + "-"*60 + "\033[0m")

        # Option to delete the log
        delete_option = input("\n\033[93mDo you want to delete this log? (y/n): \033[0m").strip().lower()
        if delete_option == 'y':
            os.remove(log_file_path)
            print(f"\033[92mLog file {selected_log} has been deleted.\033[0m")
            # After deletion, go back to the log menu
            show_logs_menu()
        else:
            print("\033[91mLog file not deleted.\033[0m")
            # After not deleting, go back to the log menu
            show_logs_menu()

    except ValueError:
        print("\033[91mInvalid input. Please enter a number.\033[0m")

def show_main_menu():
    clear_screen()
    """Display the main menu."""
    print("\n\033[1;36mWelcome to Terminal Logger.\033[0m")
    print("Type \033[93mshell\033[0m to drop into a shell session.")
    print("Type \033[93mlogs\033[0m to list and view previous logs.")
    print("Type \033[91mexit\033[0m to quit.")

def show_logs_menu():
    clear_screen()
    """Display the log file management menu."""
    print("\n\033[1;36mLog File Management.\033[0m")
    print("Type \033[93mlist\033[0m to list available logs.")
    print("Type \033[93mdelete\033[0m to delete a log.")
    print("Type \033[91mback\033[0m to go back to the main menu.")
    print("Type \033[91mexit\033[0m to quit.")
    print()

def main():
    """Main function to run the shellnote program."""
    show_main_menu()  # Show menu immediately when script starts

    while True:
        command = input("\033[93m>>> \033[0m").strip()

        if command.lower() == "shell":
            # Create a log file and start the shell
            log_file = create_log_file()
            start_shell(log_file)
            show_main_menu()  # Show the menu again after shell exit

        elif command.lower() == "logs":
            # Show logs menu for managing log files
            show_logs_menu()

            while True:
                log_command = input("\033[93m>>> \033[0m").strip()

                if log_command.lower() == "list":
                    view_logs()
                elif log_command.lower() == "back":
                    show_main_menu()
                    break
                elif log_command.lower() == "exit":
                    print("\033[91mExiting Terminal Logger.\033[0m")
                    return
                else:
                    print("\033[91mUnknown command. Type \033[93mlist\033[0m to list logs, \033[93mback\033[0m to return, or \033[91mexit\033[0m to quit.")

        elif command.lower() == "exit":
            print("\033[91mExiting Terminal Logger.\033[0m")
            return

        else:
            print("\033[91mUnknown command. Type \033[93mshell\033[0m to enter a shell, \033[93mlogs\033[0m to view logs, or \033[91mexit\033[0m to quit.")

if __name__ == "__main__":
    main()
