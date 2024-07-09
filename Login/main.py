import requests
import customtkinter as ctk
from tkinter import messagebox
import subprocess
import sqlite3
import nmap
import os
import sys
from hashlib import sha256


# Hash the password using SHA-256
def hash_password(password):
    return sha256(password.encode()).hexdigest()


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
    geobutton = ctk.CTkButton(geoip, text="Submit", command=lambda: get_geoip_data(geoentry, geotextbox),
                              corner_radius=10)
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
            messagebox.showerror("Error",
                                 f"nmap is not installed or not found. Please install nmap and try again.\n{e}")
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
    result_text = ctk.CTkTextbox(app, height=15)
    result_text.pack(pady=10, padx=10, fill='both', expand=True)

    app.mainloop()


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
