from flask import Flask, render_template, request, redirect, session
from extensions import db
from utils import encrypt_data, decrypt_data
from models import Player

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///players.db'

db.init_app(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == "admin" and password == "password":
            session['user'] = username
            return redirect('/dashboard')
        return "Invalid credentials"
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect('/')

    if request.method == 'POST':
        name = request.form['name']
        stats = request.form['stats']
        encrypted_stats = encrypt_data(stats)
        new_player = Player(name=name, stats=encrypted_stats)
        db.session.add(new_player)
        db.session.commit()

    players = Player.query.all()
    decrypted_players = [(p.name, decrypt_data(p.stats)) for p in players]
    return render_template('dashboard.html', players=decrypted_players)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

import os

@app.route('/initdb')
def initdb():
    from extensions import db
    db.create_all()
    return "Database initialized!"


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
