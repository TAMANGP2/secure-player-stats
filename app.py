from flask import Flask, render_template, request, redirect, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db
from utils import encrypt_data, decrypt_data
from models import Player, User

import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///players.db'

db.init_app(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists"

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/dashboard')
        return "Invalid credentials"

    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        name = request.form['name']
        stats = request.form['stats']
        encrypted_stats = encrypt_data(stats)
        new_player = Player(name=name, stats=encrypted_stats, user_id=current_user.id)
        db.session.add(new_player)
        db.session.commit()

    players = Player.query.filter_by(user_id=current_user.id).all()
    decrypted_players = [(p.name, decrypt_data(p.stats)) for p in players]
    return render_template('dashboard.html', players=decrypted_players)


@app.route('/initdb')
def initdb():
    with app.app_context():
        db.create_all()
    return "Database initialized!"


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
