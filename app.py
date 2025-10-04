from flask import Flask, render_template, redirect, url_for, flash, request
from forms import RegistrationForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from db import get_connection

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_super_super_secreta'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, username, password_hash):
        self.id = str(id_)
        self.username = username
        self.password_hash = password_hash

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(row["id"], row["username"], row["password_hash"])
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cursor.fetchone():
            form.username.errors.append("El usuario ya existe")
            conn.close()
            return render_template('register.html', form=form)
        hash_pw = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hash_pw))
        conn.commit()
        conn.close()
        flash("Registro exitoso. Ya puedes iniciar sesión.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        conn.close()
        if not user or not check_password_hash(user['password_hash'], password):
            flash("Credenciales inválidas", "danger")
            return render_template('login.html', form=form)
        user_obj = User(user["id"], user["username"], user["password_hash"])
        login_user(user_obj)
        flash("Inicio de sesión correcto", "success")
        return redirect(url_for('profile'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == '__main__':
    app.run(debug=True)
