from flask import Flask, render_template, request, url_for, flash, redirect, session
import hashlib
import pickle
import re
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, Regexp, Email

app = Flask(__name__)
app.secret_key = 'thisisasecretkey'

model = pickle.load(open('new_random_forest_model.pkl', 'rb'))

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=5, max=10),
        Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{5,10}$',
               message='Password must be 5-10 characters long and include at least one uppercase letter, one number, and one special character.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash('Username already registered. Please choose a different username.', 'error')
            conn.close()
            return redirect(url_for('register'))

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_email = cursor.fetchone()
        if existing_email:
            flash('Email already registered. Please use a different email.', 'error')
            conn.close()
            return redirect(url_for('register'))

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'An error occurred during registration: {str(e)}', 'error')
        finally:
            conn.close()

    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('You have been logged out!', 'success')
    return redirect(url_for('index'))

@app.route('/example')
def example():
    return render_template('example.html')

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required!', 'error')
            return redirect(url_for('index'))

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username
            flash('Login successful!', 'success')
            return render_template('index.html', url=None, predicted_site_type=None)
        else:
            flash('Invalid credentials!', 'error')
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']

    url_len = len(url)
    letter_counts = sum(c.isalpha() for c in url)
    digits_counts = sum(c.isdigit() for c in url)
    special_characters_count = sum(not c.isalnum() for c in url)
    shortend = 1 if url_len < 20 else 0
    abnormal_url = 1 if not re.match(r'^https?://', url) else 0
    secure_http = 1 if re.match(r'^https://', url) else 0
    have_ip = 1 if any(part.isdigit() and 0 <= int(part) <= 255 for part in re.findall(r'\d+', url)) else 0

    features = [[url_len,letter_counts,digits_counts,special_characters_count,shortend,abnormal_url,secure_http,have_ip]]
    prediction = model.predict(features)[0] 

    if prediction == 0:
        predicted_site_type = 'This site is safe to browse.'
    elif prediction == 1:
        predicted_site_type = 'This site is a suspicious site. Please do not enter any sensitive information.'
    elif prediction == 2:
        predicted_site_type = 'This site is a phishing site. Please do not enter any sensitive information.'
    elif prediction == 3:
        predicted_site_type = 'This site is a malicious site. Please do not enter any sensitive information.'
    else:
        predicted_site_type = 'Unknown site type.'

    return render_template('index.html', url=url, predicted_site_type=predicted_site_type)

if __name__ == '__main__':
    app.run(debug=True)
