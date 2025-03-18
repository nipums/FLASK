from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
import psycopg2

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)

# Подключение к базе данных
conn = psycopg2.connect(
    host="keribeyus.beget.app",
    port=5432,
    dbname="default_db",
    user="cloud_user",
    password="5nttoz*2kYdW",
    target_session_attrs="read-write"
)
cursor = conn.cursor()

# Создание таблиц
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password TEXT NOT NULL
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
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template("login.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            flash("Неверное имя пользователя или пароль!", "danger")

    return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id", (username, password))
            user_id = cursor.fetchone()[0]
            conn.commit()
            session['user_id'] = user_id
            session['username'] = username
            return redirect(url_for('chat'))
        except:
            flash("Пользователь уже существует!", "danger")

    return render_template("register.html")


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
    app.run(debug=True)
