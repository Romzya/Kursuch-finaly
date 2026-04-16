from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import sqlite3
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = 'payments.db'


# ─────────────────────────────────────────
# Database
# ─────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                balance REAL DEFAULT 0.0,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                amount REAL NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'completed',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            );
        """)
        # Create default admin if not exists
        admin_pw = hash_password('admin123')
        try:
            conn.execute(
                "INSERT INTO users (username, password, role, balance) VALUES (?, ?, 'admin', 0)",
                ('admin', admin_pw)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass


def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ─────────────────────────────────────────
# Decorators
# ─────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Доступ запрещён.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ? AND password = ?',
                (username, hash_password(password))
            ).fetchone()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        flash('Неверный логин или пароль.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username or not password:
            flash('Заполните все поля.', 'error')
        elif len(username) < 3:
            flash('Логин должен быть не менее 3 символов.', 'error')
        elif len(password) < 6:
            flash('Пароль должен быть не менее 6 символов.', 'error')
        elif password != confirm:
            flash('Пароли не совпадают.', 'error')
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        'INSERT INTO users (username, password, balance) VALUES (?, ?, 1000.0)',
                        (username, hash_password(password))
                    )
                    conn.commit()
                flash('Аккаунт создан. Войдите в систему.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Пользователь с таким логином уже существует.', 'error')
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ─────────────────────────────────────────
# User routes
# ─────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        txns = conn.execute("""
            SELECT t.*, 
                   s.username AS sender_name, 
                   r.username AS receiver_name
            FROM transactions t
            LEFT JOIN users s ON t.sender_id = s.id
            LEFT JOIN users r ON t.receiver_id = r.id
            WHERE t.sender_id = ? OR t.receiver_id = ?
            ORDER BY t.created_at DESC LIMIT 10
        """, (session['user_id'], session['user_id'])).fetchall()
    return render_template('dashboard.html', user=user, transactions=txns)


@app.route('/send', methods=['GET', 'POST'])
@login_required
def send_payment():
    if request.method == 'POST':
        recipient = request.form.get('recipient', '').strip()
        amount_raw = request.form.get('amount', '0')
        description = request.form.get('description', '').strip()
        try:
            amount = float(amount_raw)
        except ValueError:
            flash('Некорректная сумма.', 'error')
            return redirect(url_for('send_payment'))

        if amount <= 0:
            flash('Сумма должна быть больше нуля.', 'error')
            return redirect(url_for('send_payment'))

        with get_db() as conn:
            sender = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            receiver = conn.execute('SELECT * FROM users WHERE username = ?', (recipient,)).fetchone()

            if not receiver:
                flash('Получатель не найден.', 'error')
            elif receiver['id'] == session['user_id']:
                flash('Нельзя отправить платёж самому себе.', 'error')
            elif sender['balance'] < amount:
                flash('Недостаточно средств.', 'error')
            else:
                conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, sender['id']))
                conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, receiver['id']))
                conn.execute(
                    'INSERT INTO transactions (sender_id, receiver_id, amount, description) VALUES (?, ?, ?, ?)',
                    (sender['id'], receiver['id'], amount, description)
                )
                conn.commit()
                flash(f'Платёж {amount:.2f} ₽ успешно отправлен пользователю {recipient}.', 'success')
                return redirect(url_for('dashboard'))

    with get_db() as conn:
        users = conn.execute(
            'SELECT username FROM users WHERE id != ? AND role != "admin"',
            (session['user_id'],)
        ).fetchall()
    return render_template('send_payment.html', users=users)


# ─────────────────────────────────────────
# Admin routes
# ─────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    with get_db() as conn:
        users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
        txns = conn.execute("""
            SELECT t.*, s.username AS sender_name, r.username AS receiver_name
            FROM transactions t
            LEFT JOIN users s ON t.sender_id = s.id
            LEFT JOIN users r ON t.receiver_id = r.id
            ORDER BY t.created_at DESC LIMIT 50
        """).fetchall()
        total_users = conn.execute('SELECT COUNT(*) FROM users WHERE role != "admin"').fetchone()[0]
        total_txns = conn.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]
        total_volume = conn.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions').fetchone()[0]
    return render_template('admin.html', users=users, transactions=txns,
                           total_users=total_users, total_txns=total_txns, total_volume=total_volume)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    with get_db() as conn:
        conn.execute('DELETE FROM users WHERE id = ? AND role != "admin"', (user_id,))
        conn.commit()
    flash('Пользователь удалён.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/topup/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def topup_user(user_id):
    amount = float(request.form.get('amount', 0))
    if amount > 0:
        with get_db() as conn:
            conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
            conn.commit()
        flash(f'Баланс пополнен на {amount:.2f} ₽.', 'success')
    return redirect(url_for('admin_panel'))


# ─────────────────────────────────────────
# Run
# ─────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
