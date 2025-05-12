import os
import random
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText

import bcrypt
import pyotp
from authlib.integrations.flask_client import OAuth
from flask import Flask, request, session, render_template
from flask import redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

import config
from crypto_utils import encrypt_data, decrypt_data

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=config.OAUTH_PROVIDERS["google"]["client_id"],
    client_secret=config.OAUTH_PROVIDERS["google"]["client_secret"],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    pin_code = db.Column(db.String(6), nullable=True)
    otp_secret = db.Column(db.String(16), nullable=False)
    backup_codes = db.Column(db.Text, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    last_failed_login = db.Column(db.DateTime, nullable=True)  # Добавить в User
    webauthn_credential_id = db.Column(db.Text, nullable=True)
    webauthn_public_key = db.Column(db.Text, nullable=True)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # success / error
    reason = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

with app.app_context():
    db.create_all()

def send_email(to_email, subject, message):
    sender = "alikhan.karim2004@gmail.com"
    password = "hjvbxirqsrcmhper"
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender, password)
    msg = MIMEText(message, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    server.sendmail(sender, to_email, msg.as_string())
    server.quit()

def add_log(username, status, reason):
    ip_address = request.remote_addr  # Получаем IP пользователя
    log_entry = Log(username=username, ip_address=ip_address, status=status, reason=reason)
    db.session.add(log_entry)
    db.session.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())
        pin_code = request.form['pin_code']
        otp_secret = pyotp.random_base32()
        backup_codes = ','.join([str(random.randint(100000, 999999)) for _ in range(5)])
        encrypted_email = encrypt_data(email)

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует!', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=encrypted_email, password=password, pin_code=pin_code,
                    otp_secret=otp_secret, backup_codes=backup_codes)
        db.session.add(user)
        db.session.commit()

        send_email(email, "Ваши ключи для 2FA", f"Ваш OTP: {otp_secret}\nКоды: {backup_codes}")
        flash("Пользователь зарегистрирован.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_code = request.form['otp_code'].strip()
        pin_code = request.form['pin_code']
        user = User.query.filter_by(username=username).first()

        totp = pyotp.TOTP(user.otp_secret) if user else None
        codes = user.backup_codes.split(',') if user and user.backup_codes else []

        # если пользователь не найден
        if not user:
            add_log(username, "error", "Пользователь не найден")
            flash("Неверное имя пользователя или пароль!", "danger")
            return redirect(url_for('login'))

        # если заблокирован
        if user.failed_attempts >= 3:
            if user.last_failed_login and datetime.now() - user.last_failed_login > timedelta(minutes=5):
                user.failed_attempts = 0
                db.session.commit()
            else:
                add_log(username, "error", "Аккаунт временно заблокирован")
                flash("Аккаунт заблокирован на 5 минут. Попробуйте позже.", "danger")
                return redirect(url_for('login'))

        # если не прошел пароль
        if not bcrypt.checkpw(password.encode(), user.password):
            user.failed_attempts += 1
            user.last_failed_login = datetime.now()
            db.session.commit()
            add_log(username, "error", "Неверный пароль")
            flash(f"Неверный пароль! Осталось попыток: {3 - user.failed_attempts}", "danger")
            return redirect(url_for('login'))

        # если не прошел OTP
        if not totp.verify(otp_code) and otp_code not in codes:
            user.failed_attempts += 1
            user.last_failed_login = datetime.now()
            db.session.commit()
            add_log(username, "error", "Неверный одноразовый код")
            flash(f"Неверный одноразовый код! Осталось попыток: {3 - user.failed_attempts}", "danger")
            return redirect(url_for('login'))

        # если не прошел PIN
        if user.pin_code != pin_code:
            user.failed_attempts += 1
            user.last_failed_login = datetime.now()
            db.session.commit()
            add_log(username, "error", "Неверный PIN")
            flash(f"Неверный PIN! Осталось попыток: {3 - user.failed_attempts}", "danger")
            return redirect(url_for('login'))

        # успешный вход
        user.failed_attempts = 0  # сбрасываем счетчик
        db.session.commit()
        session['username'] = username
        session['email'] = decrypt_data(user.email)
        add_log(username, "success", "Успешный вход")
        flash("Успешный вход в систему!", "success")
        return redirect(url_for('profile'))

    return render_template('login.html')



@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', username=session['username'], email=session['email'])


@app.route('/profile/settings', methods=['GET', 'POST'])
def profile_settings():
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash("Пользователь не найден.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        if not bcrypt.checkpw(old_password.encode(), user.password):
            flash("Старый пароль неверен!", "danger")
            return redirect(url_for('profile_settings'))

        if request.form['new_password']:
            user.password = bcrypt.hashpw(request.form['new_password'].encode(), bcrypt.gensalt())

        if request.form['new_pin_code']:
            user.pin_code = request.form['new_pin_code']

        db.session.commit()
        flash("Данные обновлены!", "success")
        send_email(
            decrypt_data(user.email),
            "Ваш PIN-код был изменен",
            "Здравствуйте! Ваш PIN-код был успешно изменен. Если это были не вы, срочно свяжитесь с поддержкой."
        )

    # Проверяем, что резервные коды существуют перед вызовом split
    if user.backup_codes:
        codes = user.backup_codes.split(',')
    else:
        codes = []

    return render_template('profile_settings.html', backup_codes=codes)


@app.route('/generate_backup_codes', methods=['POST'])
def generate_backup_codes():
    if 'username' not in session:
        flash("Пожалуйста, войдите в систему.", "warning")
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    new_codes = [str(random.randint(100000, 999999)) for _ in range(5)]
    user.backup_codes = ','.join(new_codes)
    db.session.commit()
    flash("Новые резервные коды успешно сгенерированы!", "success")
    send_email(
        decrypt_data(user.email),
        "Новые резервные коды",
        f"Здравствуйте! Вы запросили новые резервные коды для входа: {', '.join(new_codes)}"
    )

    return redirect(url_for('profile_settings'))



@app.route('/change_password', methods=['POST'])
def change_password():
    user = User.query.filter_by(username=session['username']).first()
    old_password = request.form['old_password']
    new_password = request.form['new_password']

    if bcrypt.checkpw(old_password.encode(), user.password):
        user.password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        db.session.commit()
        flash("Пароль успешно изменен.", "success")
    else:
        flash("Старый пароль неверный.", "danger")
    send_email(
        decrypt_data(user.email),
        "Ваш пароль был изменен",
        "Здравствуйте! Ваш пароль был успешно изменен. Если это были не вы, срочно свяжитесь с поддержкой."
    )

    return redirect(url_for('profile'))


@app.route('/change_pin', methods=['POST'])
def change_pin():
    if 'username' not in session:
        flash("Пожалуйста, войдите в систему.", "warning")
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    old_pin = request.form['old_pin']
    new_pin = request.form['new_pin']

    if user.pin_code == str(old_pin):  # сравнение как строки
        user.pin_code = str(new_pin)  # сохраняем как строку
        db.session.commit()
        flash("PIN успешно изменен.", "success")
    else:
        flash("Неверный старый PIN.", "danger")

    return redirect(url_for('profile'))


@app.route('/admin')
def admin_panel():
    if session['username'] != 'admin':
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/reset_backup/<int:user_id>')
def admin_reset_backup(user_id):
    user = User.query.get(user_id)
    new_codes = [str(random.randint(100000, 999999)) for _ in range(5)]
    user.backup_codes = ','.join(new_codes)
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/block_user/<int:user_id>')
def admin_block_user(user_id):
    user = User.query.get(user_id)
    user.failed_attempts = 3
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/unblock_user/<int:user_id>')
def admin_unblock_user(user_id):
    user = User.query.get(user_id)
    user.failed_attempts = 0  # Снять блокировку
    db.session.commit()
    flash("Пользователь разблокирован.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    nonce = os.urandom(16).hex()
    session['nonce'] = nonce
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/authorize/google')
def authorize_google():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token, nonce=session.pop('nonce', None))

    # Проверяем, содержит ли user_info необходимую информацию
    email = user_info.get('email')
    if not email:
        flash("Не удалось получить email из профиля Google", "danger")
        return redirect(url_for('login'))

    # Проверяем, есть ли пользователь в базе данных
    user = User.query.filter_by(email=email).first()
    if not user:
        # Если пользователя нет, создаем нового
        username = email.split('@')[0]
        user = User(
            username=username,
            email=email,
            password=b'',
            otp_secret=pyotp.random_base32()
        )
        db.session.add(user)
        db.session.commit()

    # Сохраняем данные о входе в сессию
    session['username'] = user.username
    session['email'] = user.email

    # Отправляем пользователя в профиль
    flash("Вы успешно вошли через Google!", "success")
    return redirect(url_for('profile'))



@app.route('/admin/logs')
def admin_logs():
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_admin:
        flash('Доступ запрещен!', 'danger')
        return redirect(url_for('login'))
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)


if __name__ == '__main__':
    app.run(debug=True)
