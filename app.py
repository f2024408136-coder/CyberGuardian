from flask import Flask, render_template, request
import sqlite3
import re

app = Flask(__name__)


# HOME
@app.route('/')
def home():
    return "CyberGuardian Running Successfully"


# SIGNUP
@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # PASSWORD STRENGTH CHECKER
        score = 0

        if len(password) >= 8:
            score += 1

        if re.search("[A-Z]", password):
            score += 1

        if re.search("[0-9]", password):
            score += 1

        if re.search("[@#$%^&*!]", password):
            score += 1

        if score <= 1:
            strength = "Weak Password"

        elif score <= 3:
            strength = "Medium Password"

        else:
            strength = "Strong Password"

        # DATABASE
        conn = sqlite3.connect('database/users.db')

        cur = conn.cursor()

        cur.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            password TEXT
        )
        ''')

        cur.execute(
            "INSERT INTO users(name,email,password) VALUES(?,?,?)",
            (name, email, password)
        )

        conn.commit()
        conn.close()

        return strength

    return render_template('signup.html')


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database/users.db')

        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email, password)
        )

        user = cur.fetchone()

        conn.close()

        if user:

            score = 80

            return render_template(
                'dashboard.html',
                score=score
            )

        else:
            return "Invalid Email or Password"

    return render_template('login.html')


# FILE SCANNER
@app.route('/scanner', methods=['GET', 'POST'])
def scanner():

    if request.method == 'POST':

        filename = request.form['filename']

        suspicious_extensions = ['.exe', '.bat', '.vbs', '.cmd']

        for ext in suspicious_extensions:

            if filename.endswith(ext):

                result = "Warning: Suspicious File Detected"

                return render_template(
                    'scanner.html',
                    result=result
                )

        result = "File Appears Safe"

        return render_template(
            'scanner.html',
            result=result,
            filename=filename
 )

    return render_template('scanner.html')


if __name__ == '__main__':
    app.run(debug=True)