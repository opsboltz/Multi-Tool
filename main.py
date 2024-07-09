import requests
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import subprocess


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


def Geo_IP():
    global geotextbox
    geoip = ctk.CTk()
    geoip.title("Geo IP")
    geoip.geometry("400x300")
    geoentry = ctk.CTkEntry(geoip, placeholder_text="Enter Ip address")
    geoentry.pack(pady=10, padx=10)
    geobutton = ctk.CTkButton(geoip, text="Submit", command=lambda: get_geoip_data(geoentry, geotextbox),
                              corner_radius=10)
    geobutton.pack(pady=10)
    geotextbox = ctk.CTkTextbox(geoip, height=10, bg_color="Black", text_color="Grey")
    geotextbox.pack(pady=10, padx=10, fill='both', expand=True)
    geoip.mainloop()


def Pinger():
    def ping_ip():
        ip = ip_entry.get()
        try:
            result = subprocess.run(['ping', ip], capture_output=True, text=True)
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

    result_text = ctk.CTkTextbox(app, height=10)
    result_text.pack(pady=10, padx=10, fill='both', expand=True)

    app.mainloop()

def Main_Menu():
    login.withdraw()  # Hide the login frame

    Main = ctk.CTk()
    Main.title("Main Menu")
    Main.geometry("800x600")

    # Configure grid layout
    Main.grid_columnconfigure(1, weight=1)
    Main.grid_rowconfigure(0, weight=1)

    # Side Frame
    side_frame = ctk.CTkFrame(Main)
    side_frame.grid(row=0, column=0, sticky="ns", padx=20, pady=20)

    ping_button = ctk.CTkButton(side_frame, text="Ping", command=Pinger)
    ping_button.pack(pady=10, padx=50)

    geo_button = ctk.CTkButton(side_frame, text="Geo IP", command=Geo_IP)
    geo_button.pack(pady=10, padx=50)

    # Welcome Label
    label = ctk.CTkLabel(Main, text="Welcome Admin", font=("Cartoon", 32))
    label.grid(row=0, column=1, padx=10, pady=20)

    Main.mainloop()

def Login():
    Username = entry1.get()
    Password = entry2.get()
    if Username == "admin" and Password == "pass":
        messagebox.showinfo("Login Successful", "You have logged in successfully!")
        Main_Menu()
    else:
        messagebox.showerror("Login Failed", "Incorrect username or password")

login = ctk.CTk()
login.title("Login")
login.geometry("580x350")
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# Middle Frame
frame = ctk.CTkFrame(login)
frame.pack(pady=20, padx=60, fill="both", expand=True)

# Label in frame
label = ctk.CTkLabel(frame, text="Login System", font=("Cosmic", 26))
label.pack(pady=14, padx=10)

# Entry Widgets in frame
entry1 = ctk.CTkEntry(frame, placeholder_text="Username", corner_radius=10, width=180)
entry1.pack(pady=14, padx=10)
entry2 = ctk.CTkEntry(frame, placeholder_text="Password", show="*", corner_radius=10, width=180)
entry2.pack(pady=14, padx=10)

# Login Button
button = ctk.CTkButton(frame, text="Login", command=Login, corner_radius=10)
button.pack(pady=12, padx=10)

login.mainloop()
