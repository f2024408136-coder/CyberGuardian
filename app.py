from flask import Flask, render_template, request
import sqlite3
import re
import os

suspicious_count = 0

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
                score=score,
               suspicious_count=suspicious_count     

            )

        else:
            return "Invalid Email or Password"

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():

    return render_template(
        'dashboard.html',
        suspicious_count=suspicious_count
    )


# FILE SCANNER
@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    global suspicious_count
    if request.method == 'POST':

        file = request.files['file']

        filename = file.filename

        filepath = os.path.join('scans', filename)

        file.save(filepath)

        suspicious_extensions = ['.exe', '.bat', '.vbs', '.cmd']

        for ext in suspicious_extensions:

            if filename.endswith(ext):

                suspicious_count += 1

                result = "Warning: Suspicious File Detected"

                return render_template(
                    'scanner.html',
                    result=result,
                    filename=filename
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