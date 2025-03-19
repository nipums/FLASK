from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import psycopg2
import os
import random

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)
s = URLSafeTimedSerializer(app.secret_key)  # Инициализация сериализатора

# Конфигурация Mail.ru
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'cinemamaxs@mail.ru'  # Укажи свою почту Mail.ru
app.config['MAIL_PASSWORD'] = 'kVejfYzEdCWxDSTbP2bp'  # Укажи пароль от почты
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

# Создание таблицы пользователей с подтверждением email
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

# Главная страница (редирект на вход)
@app.route('/')
def home():
    return redirect(url_for('login'))


# Регистрация с подтверждением email
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # Генерация кода подтверждения
        code = random.randint(100000, 999999)
        session['verification_code'] = code
        session['pending_username'] = username
        session['pending_email'] = email
        session['pending_password'] = password

        # Отправка кода на почту
        msg = Message("Подтверждение регистрации", recipients=[email])
        msg.body = f"Ваш код подтверждения: {code}"
        mail.send(msg)

        return redirect(url_for('verify_registration'))

    return render_template("register.html")


# Восстановление пароля
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Сброс пароля", recipients=[email])
            msg.body = f'Для сброса пароля перейдите по ссылке: {reset_url}'
            mail.send(msg)
            flash("Ссылка для сброса пароля отправлена на вашу почту.", "info")
        else:
            flash("Email не найден в системе.", "danger")
    return render_template("forgot_password.html")


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # Токен действителен 1 час
    except SignatureExpired:
        flash("Срок действия ссылки истёк.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (new_password, email))
        conn.commit()
        flash("Пароль успешно изменён. Теперь вы можете войти.", "success")
        return redirect(url_for('login'))

    return render_template("reset_password.html")


# Подтверждение регистрации
@app.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    if 'pending_email' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered_code = request.form['code']
        if int(entered_code) == session['verification_code']:
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s) RETURNING id",
                    (session['pending_username'], session['pending_email'], session['pending_password'], True))
                conn.commit()
                flash("Регистрация подтверждена. Теперь вы можете войти.", "success")
            except:
                flash("Ошибка при создании пользователя. Возможно, такой email уже зарегистрирован.", "danger")
            finally:
                session.pop('verification_code', None)
                session.pop('pending_username', None)
                session.pop('pending_email', None)
                session.pop('pending_password', None)

            return redirect(url_for('login'))
        else:
            flash("Неверный код подтверждения!", "danger")

    return render_template("verify_registration.html")

# Вход с двухфакторной аутентификацией
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT id, username, password, is_verified FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            if not user[3]:
                flash("Пожалуйста, подтвердите ваш email перед входом.", "warning")
                return redirect(url_for('login'))

            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = email

            # Генерация кода 2FA
            code = random.randint(100000, 999999)
            session['2fa_code'] = code

            msg = Message("Код подтверждения", recipients=[email])
            msg.body = f"Ваш код подтверждения: {code}"
            mail.send(msg)

            return redirect(url_for('verify_2fa'))
        else:
            flash("Неверный email или пароль!", "danger")

    return render_template("login.html")

# Подтверждение входа (2FA)
@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id' not in session or '2fa_code' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_code = request.form['code']
        if int(entered_code) == session['2fa_code']:
            session.pop('2fa_code', None)
            return redirect(url_for('chat'))
        else:
            flash("Неверный код подтверждения!", "danger")

    return render_template("verify_2fa.html")

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json()
        message = data['message']
        cursor.execute("INSERT INTO messages (user_id, message) VALUES (%s, %s)", (session['user_id'], message))
        conn.commit()
        return jsonify({"status": "success"})

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
