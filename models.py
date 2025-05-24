from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    stats = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
