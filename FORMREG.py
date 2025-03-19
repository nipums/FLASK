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
app.config['SESSION_TYPE'] = 'filesystem'
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

# Подключение к базе данных
conn = psycopg2.connect(
    host="deblahofum.beget.app",
    port=5432,
    dbname="default_db",
    user="cloud_user",
    password="*Wbx58gJxioR",
    target_session_attrs="read-write"
)


@app.route('/')
def home():
    return redirect(url_for('login'))


# Регистрация
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
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s)",
                    (session['pending_username'], session['pending_email'], session['pending_password'], True))
                conn.commit()
            except psycopg2.Error as e:
                flash("Ошибка базы данных!", "danger")
                print("Database error:", e)
            finally:
                cursor.close()
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
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password, is_verified FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and bcrypt.check_password_hash(user[2], password):
                if not user[3]:
                    flash("Подтвердите email!", "warning")
                    return redirect(url_for('login'))

                session['user_id'] = user[0]
                session['username'] = user[1]
                session['email'] = email
                session.permanent = True

                code = random.randint(100000, 999999)
                session['2fa_code'] = code

                msg = Message("Код подтверждения", recipients=[email])
                msg.body = f"Ваш код: {code}"
                mail.send(msg)

                return redirect(url_for('verify_2fa'))
            else:
                flash("Неверные данные!", "danger")

        except psycopg2.Error as e:
            flash("Ошибка базы данных!", "danger")
            print("Database error:", e)
        finally:
            cursor.close()

    return render_template("login.html")


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if int(request.form['code']) == session['2fa_code']:
            session['authenticated'] = True
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
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO messages (user_id, message) VALUES (%s, %s)", (session['user_id'], message))
                conn.commit()
                return jsonify({"status": "success"})
            except psycopg2.Error as e:
                print("Database error:", e)
                return jsonify({"status": "error", "message": "Ошибка базы данных!"})
            finally:
                cursor.close()
        else:
            return jsonify({"status": "error", "message": "Сообщение не может быть пустым"})

    return render_template("chat.html", username=session['username'])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                token = s.dumps(email, salt='password-reset')
                reset_url = url_for('reset_password', token=token, _external=True)
                msg = Message("Сброс пароля", recipients=[email])
                msg.body = f'Для сброса пароля перейдите по ссылке: {reset_url}'
                mail.send(msg)
                flash("Ссылка для сброса пароля отправлена!", "info")
            else:
                flash("Email не найден!", "danger")

        except psycopg2.Error as e:
            flash("Ошибка базы данных!", "danger")
            print("Database error:", e)

        finally:
            cursor.close()

    return render_template("forgot_password.html")


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash("Срок действия ссылки истёк!", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (new_password, email))
            conn.commit()
            flash("Пароль изменён!", "success")
        except psycopg2.Error as e:
            flash("Ошибка базы данных!", "danger")
            print("Database error:", e)
        finally:
            cursor.close()

        return redirect(url_for('login'))

    return render_template("reset_password.html")

@app.route('/messages')
def get_messages():
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT users.username, messages.message FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp ASC")
        messages = cursor.fetchall()
        return jsonify([{"username": m[0], "message": m[1]} for m in messages])
    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({"status": "error", "message": "Ошибка загрузки сообщений!"})
    finally:
        cursor.close()


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

