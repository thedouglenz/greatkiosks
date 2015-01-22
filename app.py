from __future__ import print_function
import os, datetime, calendar
from flask import Flask, jsonify, request, abort, redirect, render_template, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_required, login_user, current_user, logout_user
from flask.ext.bcrypt import Bcrypt
from marshmallow import Serializer

import json

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
app.secret_key = "\xcf\x87\xb9_~\xf9t\xb3\x1es\x87\\\xd5\x16FJ\xb7\xc3^mD'IZ"
login_manager = LoginManager(app)
@login_manager.user_loader
def load_user(id):
	return User.query.get(int(id))

class User(db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String, unique=True, nullable=False)
	password = db.Column(db.String, nullable=False)
	organization = db.Column(db.String, nullable=False)
	last_active_date = db.Column(db.DateTime(timezone=True), index=True)

	def __init__(self, email, password):
		self.email = email
		self.password = password

	def is_authenticated(self):
		return True

	def is_active(self):
		return True

	def is_anonymous(self):
		return False

	def get_id(self):
		return unicode(self.id)

	class Serializer(Serializer):
		class Meta:
			fields = ("id", "email", "organization", "last_active_date")

class Kiosk(db.Model):
	__tablename__ = 'kiosks'

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String, nullable=False)
	created = db.Column(db.DateTime)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

	user = db.relationship('User', backref=db.backref('kiosks', lazy='dynamic'))

	def __init__(self, name, created):
		self.name = name
		self.created = created

class File(db.Model):
	__tablename__ = 'files'

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String, nullable=False)
	description = db.Column(db.String, nullable=True)
	filetype = db.Column(db.String, nullable=True)
	rl = db.Column(db.String, nullable=False)

	def __init__(self, name, description, filetype, rl):
		self.name = name
		self.description = description
		self.filetype = filetype
		self.rl = rl

@app.route('/create_db')
def create_db():
	db.create_all()
	return "Database generated"

@app.route('/')
def index():
	if current_user.is_authenticated(): # they're already logged in
		return redirect(url_for('dashboard'))
	else:
		return render_template('home.html');

@app.route('/user/register')
def register_user():
	return render_template('register.html')

@app.route('/user/register', methods=['POST'])
def register_user_post():
	exists = User.query.filter(db.func.lower(User.email) == request.form['email'].lower()).first()
	if exists:
		return "This user already exists"
	hashword = bcrypt.generate_password_hash(request.form['password'])
	new_user = User(request.form['email'], hashword)
	db.session.add(new_user)
	db.session.commit()
	login_user(new_user)
	return redirect(url_for('dashboard'))

@app.route('/login', methods=['POST'])
def login():
	user = User.query.filter(db.func.lower(User.email) == request.form['email'].lower()).first()
	if user and bcrypt.check_password_hash(user.password, request.form['password']):
		login_user(user)
		return redirect(url_for('dashboard'))
	else:
		abort(401)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))

@app.route('/dashbaord')
@login_required
def dashboard():
	#
	# do some cool stuff
	#
	return render_template('dashboard.html')
