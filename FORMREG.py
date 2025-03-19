from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import psycopg2
import os
import random
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SESSION_TYPE'] = 'filesystem'  # Хранение сессий в файлах
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
Session(app)

bcrypt = Bcrypt(app)
s = URLSafeTimedSerializer(app.secret_key)

# Конфигурация почты
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'cinemamaxs@mail.ru'
app.config['MAIL_PASSWORD'] = 'kVejfYzEdCWxDSTbP2bp'
app.config['MAIL_DEFAULT_SENDER'] = 'cinemamaxs@mail.ru'
mail = Mail(app)

# Подключение к базе данных PostgreSQL
conn = psycopg2.connect(
    host="deblahofum.beget.app",
    port=5432,
    dbname="default_db",
    user="cloud_user",
    password="*Wbx58gJxioR",
    target_session_attrs="read-write"
)
cursor = conn.cursor()

# Создание таблиц, если их нет
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')
conn.commit()

@app.route('/')
def home():
    return redirect(url_for('login'))

# Регистрация с email подтверждением
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        code = random.randint(100000, 999999)
        session['verification_code'] = code
        session['pending_username'] = username
        session['pending_email'] = email
        session['pending_password'] = password

        msg = Message("Подтверждение регистрации", recipients=[email])
        msg.body = f"Ваш код подтверждения: {code}"
        mail.send(msg)

        return redirect(url_for('verify_registration'))
    return render_template("register.html")

@app.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    if 'pending_email' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        if int(request.form['code']) == session['verification_code']:
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s)",
                    (session['pending_username'], session['pending_email'], session['pending_password'], True))
                conn.commit()
                flash("Регистрация подтверждена!", "success")
            except:
                flash("Ошибка! Такой email уже зарегистрирован.", "danger")
            finally:
                session.clear()
            return redirect(url_for('login'))
        else:
            flash("Неверный код!", "danger")
    return render_template("verify_registration.html")

# Вход с 2FA
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor.execute("SELECT id, username, password, is_verified FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            if not user[3]:
                flash("Подтвердите email!", "warning")
                return redirect(url_for('login'))

            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = email
            session.permanent = True  # Долговременная сессия

            code = random.randint(100000, 999999)
            session['2fa_code'] = code

            msg = Message("Код подтверждения", recipients=[email])
            msg.body = f"Ваш код: {code}"
            mail.send(msg)

            return redirect(url_for('verify_2fa'))
        else:
            flash("Неверные данные!", "danger")
    return render_template("login.html")

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if int(request.form['code']) == session['2fa_code']:
            session['authenticated'] = True  # Подтверждаем вход
            session.pop('2fa_code', None)
            return redirect(url_for('chat'))
        else:
            flash("Неверный код!", "danger")
    return render_template("verify_2fa.html")


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session or not session.get('authenticated'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json()
        message = data.get('message', '').strip()

        if message:
            cursor.execute("INSERT INTO messages (user_id, message) VALUES (%s, %s)", (session['user_id'], message))
            conn.commit()
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "Сообщение не может быть пустым"})

    return render_template("chat.html", username=session['username'])


@app.route('/messages')
def get_messages():
    cursor.execute("SELECT users.username, messages.message FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp ASC")
    messages = cursor.fetchall()
    return jsonify([{"username": m[0], "message": m[1]} for m in messages])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
