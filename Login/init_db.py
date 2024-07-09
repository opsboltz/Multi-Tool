import sqlite3
from hashlib import sha256
import os


os.remove("user_data.db")
# Initialize the database and create the users table
def init_db():
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    #Getting password
    pazz = input("What do you want your password to be:")
    print("your Username is admin")
    # Insert admin user if not exists
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone() is None:
        #Pass
        admin_password = sha256(pazz.encode()).hexdigest()
        #Username
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', admin_password))
        conn.commit()

    conn.close()

# Run the database initialization
init_db()