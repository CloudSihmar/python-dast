from flask import Flask, render_template, request, redirect, url_for, session
import hashlib
import requests

app = Flask(__name__)
app.secret_key = b'secret_key_for_flask'

# Dummy user data for authentication
users = {'admin': 'adminpass', 'user1': 'user1pass'}

# Vulnerability: Injection (SQL Injection)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerable SQL query (DO NOT use this in real applications)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        # Do something with the query (e.g., execute it against a database)
        # ...

        # Authenticate user
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))

        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

# Vulnerability: Server-Side Request Forgery (SSRF)
@app.route('/ssrf', methods=['GET'])
def ssrf():
    url = request.args.get('url', 'http://example.com')
    response = requests.get(url)
    return f"SSRF Test: {response.text}"

# Dashboard route with broken access control
@app.route('/dashboard')
def dashboard():
    # Broken access control (any authenticated user can access the dashboard)
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    # Session management issue (no session invalidation on logout)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

