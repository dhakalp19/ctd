import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import paramiko
import threading

# Global variables to store login information
server_ip = ""
username = ""
password = ""

# Available commands categorized by sections
command_dict = {
    "Network": ["network show", "arp"],
    "Time": ["time show local"],
    "System Check": ["disk_status", "platform service status"],
    "Logs": ["cat /var/log/syslog"]
}

# Function to test SSH connection
def test_ssh_connection(ip, user, pwd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Try to connect
        ssh.connect(ip, username=user, password=pwd, timeout=5)
        ssh.close()
        return True
    except Exception as e:
        return str(e)

# Function to execute SSH command in real-time
def run_ssh_command(command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the server
        ssh.connect(server_ip, username=username, password=password, timeout=5)
        
        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # Read the output in real-time and update the UI
        output_box.delete(1.0, tk.END)  # Clear previous output
        for line in iter(stdout.readline, ""):
            output_box.insert(tk.END, line)
            output_box.see(tk.END)  # Scroll to the bottom
            root.update()  # Refresh the GUI

        # Close SSH connection
        ssh.close()

    except Exception as e:
        output_box.insert(tk.END, f"Error: {str(e)}\n")

# Function to handle login and switch to command interface
def login():
    global server_ip, username, password
    server_ip = ip_entry.get().strip()
    username = username_entry.get().strip()
    password = password_entry.get().strip()

    if not server_ip or not username or not password:
        messagebox.showwarning("Input Error", "Please fill in all fields before connecting.")
        return

    # Test connection
    connection_result = test_ssh_connection(server_ip, username, password)
    if connection_result == True:
        messagebox.showinfo("Success", "✅ Login Successful!")
        show_command_interface()
    else:
        messagebox.showerror("Connection Failed", f"❌ Connection Error: {connection_result}")

# Function to switch to the command interface
def show_command_interface():
    # Clear the login screen
    for widget in root.winfo_children():
        widget.destroy()

    root.title("SSH Command Executor")
    root.geometry("600x500")

    # Frame for dropdown selection
    command_frame = tk.Frame(root, padx=20, pady=10)
    command_frame.pack(fill="x", pady=10)

    tk.Label(command_frame, text="Select Command Category:", font=("Arial", 12)).pack(anchor="w")
    
    # Create category dropdown
    global category_var
    category_var = tk.StringVar()
    category_dropdown = ttk.Combobox(command_frame, textvariable=category_var, font=("Arial", 12), state="readonly")
    category_dropdown['values'] = list(command_dict.keys())
    category_dropdown.pack(fill="x", pady=5)
    category_dropdown.bind("<<ComboboxSelected>>", update_command_dropdown)

    tk.Label(command_frame, text="Select Command:", font=("Arial", 12)).pack(anchor="w")
    
    # Create command dropdown
    global command_var
    command_var = tk.StringVar()
    global command_dropdown
    command_dropdown = ttk.Combobox(command_frame, textvariable=command_var, font=("Arial", 12), state="readonly")
    command_dropdown.pack(fill="x", pady=5)

    # Run Command Button
    execute_button = tk.Button(command_frame, text="Run Command", command=start_command_thread, bg="green", fg="white", font=("Arial", 12, "bold"), relief="flat", padx=10, pady=5)
    execute_button.pack(pady=5)

    # Frame for output
    output_frame = tk.Frame(root, padx=20, pady=10)
    output_frame.pack(fill="both", expand=True)

    tk.Label(output_frame, text="Command Output:", font=("Arial", 12)).pack(anchor="w")
    global output_box
    output_box = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=70, height=15, font=("Courier New", 11), relief="solid")
    output_box.pack(fill="both", expand=True, pady=5)

# Update command dropdown when category changes
def update_command_dropdown(event):
    selected_category = category_var.get()
    if selected_category in command_dict:
        command_dropdown['values'] = command_dict[selected_category]
        command_dropdown.current(0)

# Function to execute command in a separate thread to avoid UI freezing
def start_command_thread():
    command = command_var.get().strip()
    if not command:
        messagebox.showwarning("Input Error", "Please select a command to execute.")
        return

    # Run command in a separate thread to avoid blocking the GUI
    threading.Thread(target=run_ssh_command, args=(command,), daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("SSH Command Login")
root.geometry("400x250")
root.configure(bg="#f5f5f5")

# Login Screen
login_frame = tk.Frame(root, padx=20, pady=20, bg="#f5f5f5")
login_frame.pack(expand=True)

tk.Label(login_frame, text="Server IP:", font=("Arial", 12), bg="#f5f5f5").grid(row=0, column=0, sticky="w", pady=5)
ip_entry = tk.Entry(login_frame, width=30, font=("Arial", 12), relief="solid")
ip_entry.grid(row=0, column=1, pady=5, padx=5)

tk.Label(login_frame, text="Username:", font=("Arial", 12), bg="#f5f5f5").grid(row=1, column=0, sticky="w", pady=5)
username_entry = tk.Entry(login_frame, width=30, font=("Arial", 12), relief="solid")
username_entry.grid(row=1, column=1, pady=5, padx=5)

tk.Label(login_frame, text="Password:", font=("Arial", 12), bg="#f5f5f5").grid(row=2, column=0, sticky="w", pady=5)
password_entry = tk.Entry(login_frame, width=30, show="*", font=("Arial", 12), relief="solid")
password_entry.grid(row=2, column=1, pady=5, padx=5)

# Login Button
login_button = tk.Button(login_frame, text="Login", command=login, bg="blue", fg="white", font=("Arial", 12, "bold"), relief="flat", padx=10, pady=5)
login_button.grid(row=3, column=1, pady=10, sticky="e")

# Run Tkinter Main Loop
root.mainloop()




#this is a test github
# test02