from flask import Flask, render_template, request, redirect, url_for, session, send_file
import sqlite3
import re
import os
import io
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors


def get_password_score(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search("[A-Z]", password):
        score += 1
    if re.search("[0-9]", password):
        score += 1
    if re.search("[@#$%^&*!]", password):
        score += 1
    return score


def count_weak_passwords():
    try:
        conn = sqlite3.connect('database/users.db')
        cur = conn.cursor()
        cur.execute("SELECT password FROM users")
        rows = cur.fetchall()
        conn.close()
        weak = 0
        for row in rows:
            if get_password_score(row[0]) <= 1:
                weak += 1
        return weak
    except:
        return 0


def get_password_distribution():
    try:
        conn = sqlite3.connect('database/users.db')
        cur = conn.cursor()
        cur.execute("SELECT password FROM users")
        rows = cur.fetchall()
        conn.close()
        weak = medium = strong = 0
        for row in rows:
            score = get_password_score(row[0])
            if score <= 1:
                weak += 1
            elif score <= 3:
                medium += 1
            else:
                strong += 1
        return {'weak': weak, 'medium': medium, 'strong': strong}
    except:
        return {'weak': 0, 'medium': 0, 'strong': 0}


def get_scan_distribution():
    try:
        conn = sqlite3.connect('database/users.db')
        cur = conn.cursor()
        cur.execute("SELECT result FROM scan_history")
        rows = cur.fetchall()
        conn.close()
        safe = suspicious = 0
        for row in rows:
            if 'Safe' in row[0]:
                safe += 1
            elif 'Suspicious' in row[0] or 'Warning' in row[0]:
                suspicious += 1
        return {'safe': safe, 'suspicious': suspicious}
    except:
        return {'safe': 0, 'suspicious': 0}

suspicious_count = 0

app = Flask(__name__)
app.secret_key = 'cyberguardian_secret_key_2026'


def get_recommendations(weak_count, suspicious_count, security_score):
    tips = []

    if weak_count > 0:
        tips.append({
            'priority': 'high',
            'icon': '🔐',
            'title': 'Strengthen Weak Passwords',
            'detail': 'You have ' + str(weak_count) + ' weak password(s). Use at least 12 characters with uppercase, lowercase, numbers, and symbols (e.g., @#$%).'
        })

    if suspicious_count > 0:
        tips.append({
            'priority': 'high',
            'icon': '⚠️',
            'title': 'Suspicious Files Detected',
            'detail': 'Avoid downloading executable files (.exe, .bat, .vbs, .cmd) from untrusted sources. Always verify the source before running.'
        })

    if security_score < 50:
        tips.append({
            'priority': 'high',
            'icon': '🚨',
            'title': 'Critical: Improve Security Score',
            'detail': 'Your security score is critically low. Address weak passwords and remove suspicious files immediately to improve your security posture.'
        })
    elif security_score < 80:
        tips.append({
            'priority': 'medium',
            'icon': '📊',
            'title': 'Moderate Security Level',
            'detail': 'Your security needs attention. Review password strengths and scan results to identify improvement areas.'
        })

    tips.append({
        'priority': 'medium',
        'icon': '🔒',
        'title': 'Enable Two-Factor Authentication',
        'detail': 'Add an extra layer of security by enabling 2FA on all your important accounts (email, social media, banking).'
    })

    tips.append({
        'priority': 'medium',
        'icon': '🔄',
        'title': 'Keep Software Updated',
        'detail': 'Regularly update your operating system, browser, and applications to patch known security vulnerabilities.'
    })

    tips.append({
        'priority': 'low',
        'icon': '🌐',
        'title': 'Use Secure Connections',
        'detail': 'Always verify the website URL starts with HTTPS before entering sensitive information. Avoid public Wi-Fi for banking.'
    })

    tips.append({
        'priority': 'low',
        'icon': '💾',
        'title': 'Backup Important Data',
        'detail': 'Regularly back up your important files to an external drive or trusted cloud storage to prevent data loss from ransomware.'
    })

    tips.append({
        'priority': 'low',
        'icon': '📧',
        'title': 'Beware of Phishing Emails',
        'detail': 'Do not click on suspicious links or download attachments from unknown senders. Verify the sender before any action.'
    })

    return tips


def check_url_safety(url):
    if not url:
        return None

    issues = []
    score = 100

    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()
    except:
        return {
            'url': url,
            'safe': False,
            'score': 0,
            'issues': ['Invalid URL format'],
            'verdict': 'Invalid URL'
        }

    if not url.startswith('https://'):
        issues.append('Not using HTTPS (insecure connection)')
        score -= 30

    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
        issues.append('Uses IP address instead of domain name (suspicious)')
        score -= 25

    if domain.count('-') > 3:
        issues.append('Domain contains excessive hyphens (often used in phishing)')
        score -= 15

    if len(domain) > 50:
        issues.append('Unusually long domain name')
        score -= 10

    if full.count('@') > 0 and not full.startswith('mailto:'):
        issues.append('Contains @ symbol (possible URL obfuscation)')
        score -= 25

    suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank', 'paypal', 'confirm']
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']

    keyword_count = sum(1 for kw in suspicious_keywords if kw in path)
    if keyword_count >= 2:
        issues.append('Multiple suspicious keywords in URL path')
        score -= 15

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            issues.append('Uses suspicious top-level domain (' + tld + ')')
            score -= 20
            break

    if 'bit.ly' in domain or 'tinyurl' in domain or 'goo.gl' in domain or 't.co' in domain:
        issues.append('Shortened URL - actual destination is hidden')
        score -= 10

    score = max(0, score)

    if score >= 80:
        verdict = 'Safe'
    elif score >= 50:
        verdict = 'Suspicious'
    else:
        verdict = 'Dangerous'

    return {
        'url': url,
        'safe': score >= 80,
        'score': score,
        'issues': issues if issues else ['No security issues detected'],
        'verdict': verdict
    }


# HOME
@app.route('/')
def home():
    return redirect(url_for('login'))


# SIGNUP
@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # PASSWORD STRENGTH CHECKER
        score = get_password_score(password)

        if score <= 1:
            strength = "Weak"
        elif score <= 3:
            strength = "Medium"
        else:
            strength = "Strong"

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

        # Check if email already exists
        cur.execute("SELECT * FROM users WHERE email=?", (email,))
        existing = cur.fetchone()

        if existing:
            conn.close()
            return render_template('signup.html', error="Email already registered. Please login.")

        cur.execute(
            "INSERT INTO users(name,email,password) VALUES(?,?,?)",
            (name, email, password)
        )

        conn.commit()
        conn.close()

        return render_template(
            'login.html',
            success="Account created successfully! Password Strength: " + strength + ". Please login."
        )

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
            session['user_email'] = email
            session['user_name'] = user[1]
            return redirect(url_for('dashboard'))

        else:
            return render_template('login.html', error="Invalid Email or Password")

    return render_template('login.html')
@app.route('/dashboard')
def dashboard():

    try:

        url = "https://thehackernews.com"

        response = requests.get(url)

        soup = BeautifulSoup(response.text, "html.parser")

        headlines = soup.find_all("h2")

        threat1 = headlines[0].text.strip()
        threat2 = headlines[1].text.strip()
        threat3 = headlines[2].text.strip()

    except:

        threat1 = "Unable to Fetch Security Alerts"
        threat2 = "Check Internet Connection"
        threat3 = "Try Again Later"

    # DYNAMIC SECURITY SCORE

    weak_count = count_weak_passwords()

    if suspicious_count == 0:
        security_score = 100

    elif suspicious_count == 1:
        security_score = 80

    elif suspicious_count == 2:
        security_score = 60

    else:
        security_score = 40

    # Deduct points for weak passwords
    security_score = max(0, security_score - (weak_count * 10))

    pwd_dist = get_password_distribution()
    scan_dist = get_scan_distribution()

    return render_template(
        'dashboard.html',
        suspicious_count=suspicious_count,
        threat1=threat1,
        threat2=threat2,
        threat3=threat3,
        security_score=security_score,
        weak_count=weak_count,
        pwd_weak=pwd_dist['weak'],
        pwd_medium=pwd_dist['medium'],
        pwd_strong=pwd_dist['strong'],
        scan_safe=scan_dist['safe'],
        scan_suspicious=scan_dist['suspicious']
    )
# FILE SCANNER
@app.route('/scanner', methods=['GET', 'POST'])
def scanner():

    global suspicious_count

    conn = sqlite3.connect('database/users.db')

    cur = conn.cursor()

    cur.execute('''
    CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        result TEXT,
        scan_time TEXT
    )
    ''')

    cur.execute(
        "SELECT filename, result, scan_time FROM scan_history ORDER BY id DESC"
    )

    history = cur.fetchall()

    conn.close()

    if request.method == 'POST':

        file = request.files['file']

        if file.filename == '':

            return render_template(
                'scanner.html',
                result='Please Select a File First',
                history=history
            )

        filename = file.filename

        filepath = os.path.join('scans', filename)

        file.save(filepath)

        suspicious_extensions = ['.exe', '.bat', '.vbs', '.cmd']

        for ext in suspicious_extensions:

            if filename.endswith(ext):

                suspicious_count += 1

                result = "Warning: Suspicious File Detected"

                current_time = datetime.now().strftime("%d-%m-%Y %I:%M %p")

                conn = sqlite3.connect('database/users.db')

                cur = conn.cursor()

                cur.execute(
                    "INSERT INTO scan_history(filename,result,scan_time) VALUES(?,?,?)",
                    (filename, result, current_time)
                )

                conn.commit()
                conn.close()

                return render_template(
                    'scanner.html',
                    result=result,
                    filename=filename,
                    history=history
                )

        result = "File Appears Safe"

        current_time = datetime.now().strftime("%d-%m-%Y %I:%M %p")

        conn = sqlite3.connect('database/users.db')

        cur = conn.cursor()

        cur.execute(
            "INSERT INTO scan_history(filename,result,scan_time) VALUES(?,?,?)",
            (filename, result, current_time)
        )

        conn.commit()
        conn.close()

        return render_template(
            'scanner.html',
            result=result,
            filename=filename,
            history=history
        )

    return render_template(
        'scanner.html',
        history=history
    )

# SECURITY RECOMMENDATIONS
@app.route('/recommendations')
def recommendations():
    weak_count = count_weak_passwords()

    if suspicious_count == 0:
        security_score = 100
    elif suspicious_count == 1:
        security_score = 80
    elif suspicious_count == 2:
        security_score = 60
    else:
        security_score = 40

    security_score = max(0, security_score - (weak_count * 10))

    tips = get_recommendations(weak_count, suspicious_count, security_score)

    return render_template(
        'recommendations.html',
        tips=tips,
        weak_count=weak_count,
        suspicious_count=suspicious_count,
        security_score=security_score
    )


# REPORT GENERATION (PDF Download)
@app.route('/report')
def report():
    weak_count = count_weak_passwords()

    if suspicious_count == 0:
        security_score = 100
    elif suspicious_count == 1:
        security_score = 80
    elif suspicious_count == 2:
        security_score = 60
    else:
        security_score = 40

    security_score = max(0, security_score - (weak_count * 10))

    conn = sqlite3.connect('database/users.db')
    cur = conn.cursor()
    cur.execute("SELECT filename, result, scan_time FROM scan_history ORDER BY id DESC LIMIT 10")
    scan_history = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=40, bottomMargin=40)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Title'],
        fontSize=24,
        textColor=HexColor('#0a4d8c'),
        spaceAfter=12
    )
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=HexColor('#0a4d8c'),
        spaceAfter=8,
        spaceBefore=12
    )
    normal_style = styles['Normal']

    story = []

    story.append(Paragraph('CyberGuardian Security Report', title_style))
    story.append(Paragraph('Generated on: ' + datetime.now().strftime('%d %B %Y, %I:%M %p'), normal_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph('Executive Summary', heading_style))
    summary_data = [
        ['Metric', 'Value'],
        ['Security Score', str(security_score) + '%'],
        ['Total Registered Users', str(total_users)],
        ['Weak Passwords Detected', str(weak_count)],
        ['Suspicious Files Found', str(suspicious_count)],
    ]
    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a4d8c')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f0f7ff')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph('Risk Assessment', heading_style))
    if security_score >= 80:
        risk_text = '<b>LOW RISK</b> — Your overall security posture is strong. Continue following best practices.'
    elif security_score >= 50:
        risk_text = '<b>MEDIUM RISK</b> — Some security concerns require attention. Review weak passwords and scan results.'
    else:
        risk_text = '<b>HIGH RISK</b> — Immediate action required. Critical security issues detected.'
    story.append(Paragraph(risk_text, normal_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph('Recent Scan History', heading_style))
    if scan_history:
        scan_data = [['File Name', 'Result', 'Time']]
        for item in scan_history:
            scan_data.append([item[0][:30], item[1][:30], item[2]])
        scan_table = Table(scan_data, colWidths=[180, 180, 120])
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a4d8c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(scan_table)
    else:
        story.append(Paragraph('No scan history available.', normal_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph('Security Recommendations', heading_style))
    tips = get_recommendations(weak_count, suspicious_count, security_score)
    for i, tip in enumerate(tips, 1):
        tip_text = '<b>' + str(i) + '. ' + tip['title'] + '</b><br/>' + tip['detail']
        story.append(Paragraph(tip_text, normal_style))
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        '<i>This report is generated by CyberGuardian — Personal Security Audit System. For educational and awareness purposes only.</i>',
        normal_style
    ))

    doc.build(story)
    buffer.seek(0)

    filename = 'CyberGuardian_Report_' + datetime.now().strftime('%Y%m%d_%H%M') + '.pdf'
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )


# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# URL SAFETY CHECKER
@app.route('/url-check', methods=['GET', 'POST'])
def url_check():
    result = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        result = check_url_safety(url)

    return render_template('url_check.html', result=result)


if __name__ == '__main__':
    app.run(debug=True)