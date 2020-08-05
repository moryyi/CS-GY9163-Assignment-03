#!/usr/bin/python3
# coding: utf-8


from flask import Flask, request, render_template, session, logging, url_for, redirect, flash
from flask import make_response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_paranoid import Paranoid
from wtforms.validators import DataRequired
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from werkzeug.security import generate_password_hash, check_password_hash
import base64, hashlib, random, string
import subprocess
import sys, os
import datetime

from src.myModels import db, User, LoginLog, Query
from src.myForms import RegisterForm, LoginForm, ContentForm, AdminLoginLogQueryForm, AdminQueryCheckForm


USER_DATABASE = {}

ROOT_URL = ""

def configure_routes(app):

	# Initialize database
	db.init_app(app)
	with app.app_context():
		db.drop_all()
		db.create_all()
		admin = User(
			username='admin',
			password=generate_password_hash('Administrator@1'),
			phone='12345678901',
			ifAdmin=True
		)
		db.session.add(admin)
		db.session.commit()

	# Content-Security-Headers
	@app.after_request
	def add_security_headers(resp):
		resp.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' stackpath.bootstrapcdn.com;"
		resp.headers['X-Frame-Options'] = "SAMEORIGIN"
		resp.headers['X-Content-Type-Options'] = "nosniff"
		resp.headers['X-XSS-Protection'] = '1; mode=block'
		return resp

	# Login
	@app.route(ROOT_URL + '/login', methods=['GET', 'POST'])
	def login():
		if "log" in session and session["log"]:
			resp = make_response(redirect(url_for('spell_check')))
			return resp
		
		form = LoginForm()
		if form.validate_on_submit():
			username = form.username.data
			password = form.password.data
			phone = form.phone.data

			(ifLoginSuccess, errorMessage) = login_with_user_info(username, password, phone)
			if ifLoginSuccess:
				session["log"] = True
				session["session_id"] = gen_random_string(16)
				session.permanent = True
				# Clear the previous un-logout activity record
				unlogout_records = LoginLog.query\
																	.filter((LoginLog.uid == session["uid"]) & (LoginLog.logoutTime == None))\
																	.all()
				for r in unlogout_records:
					r.logoutTime = datetime.datetime.utcnow()
					db.session.commit()

				# Log this login activity
				new_login = LoginLog(uid=session["uid"])
				db.session.add(new_login)
				db.session.commit()
				flash(["result", errorMessage], "success")
				resp = make_response(redirect(url_for('spell_check')))
				resp.set_cookie('session_id', session["session_id"], httponly=True, samesite='Lax')
				return resp
			else:
				flash(["result", errorMessage], "danger")
		resp = make_response(render_template("./login.html", form=form))
		return resp


	# Logout
	@app.route(ROOT_URL + '/logout', methods=['GET'])
	def logout():
		if "uid" not in session:
			pass
		else:
			# Update table Logs for logoutTime record
			current_log = LoginLog.query.filter_by(uid=session["uid"]).order_by(LoginLog.rid.desc()).first()
			if current_log != None:
				current_log.logoutTime = datetime.datetime.utcnow()
				db.session.commit()

		session.clear()
		return redirect(url_for("login"))


	# Registeration
	@app.route(ROOT_URL + '/register', methods=['GET', 'POST'])
	def register():
		if "log" in session and session["log"]:
			resp = make_response(redirect(url_for('spell_check')))
			return resp
		form = RegisterForm()
		if form.validate_on_submit():
			username = form.username.data
			password = form.password.data
			phone = form.phone.data

			(ifRegisterSuccess, errorMessage) = register_with_user_info(username, password, phone)
			if not ifRegisterSuccess:
				flash(["success", errorMessage], "danger")
			else:
				flash(["success", errorMessage], "success")
				resp = make_response(redirect(url_for('login')))
				# resp = make_response(render_template("./register.html", form=form))
				return resp
		resp = make_response(render_template("./register.html", form=form))
		return resp


	# Spell-Check
	@app.route(ROOT_URL + '/spell_check', methods=['GET', 'POST'])
	def spell_check():
		form = ContentForm()
		if form.validate_on_submit():
			content = form.inputtext.data
			misspelled_words = check_text_spelling(content)
			response = [content, misspelled_words]
			current_query = Query(
				uid=session["uid"],
				qtext=content,
				qresult=misspelled_words
			)
			db.session.add(current_query)
			db.session.commit()
			resp = make_response(render_template('./spell.html', response=response, form=form))
			return resp

		else:
			if "log" in session and session["log"]:
				resp = make_response(render_template('./spell.html', form=form))
				return resp
			else:
				resp = make_response(redirect(url_for('login')))
				return resp


	# Record History
	# Page containing all query urls
	@app.route(ROOT_URL + '/history', methods=['GET', 'POST'])
	def history():
		if "log" not in session or session["log"] == False:
			flash(["error", "You are not login"], "danger")
			resp = make_response(redirect(url_for("spell_check")))
			return resp
		form = AdminQueryCheckForm()
		if session["ifAdmin"] != True:
			queries = Query.query\
												.join(User, User.uid == Query.uid)\
												.add_columns(Query.qid, Query.uid, User.username, Query.qtext, Query.qresult)\
												.filter_by(uid=session["uid"]).all()
		else:
			if form.validate_on_submit():
				userquery = form.userquery.data
				if userquery != '':
					existing_user = User.query.filter_by(username=userquery).first()
					if existing_user != None:
						queries = Query.query\
													.join(User, User.uid == Query.uid)\
													.add_columns(Query.qid, Query.uid, User.username, Query.qtext, Query.qresult)\
													.filter_by(uid=existing_user.uid).all()
					else:
						queries = []
				else:
					queries = Query.query\
												.join(User, User.uid == Query.uid)\
												.add_columns(Query.qid, Query.uid, User.username, Query.qtext, Query.qresult)\
												.all()
			else:
				queries = Query.query\
												.join(User, User.uid == Query.uid)\
												.add_columns(Query.qid, Query.uid, User.username, Query.qtext, Query.qresult)\
												.all()
		resp = make_response(render_template("./history.html", queries=queries, form=form))
		return resp


	# Page for each query record
	@app.route(ROOT_URL + '/history/query<int:qid>', methods=['GET'])
	def checkQueryByQid(qid):
		print("qid: {}".format(qid))
		if "log" not in session or session["log"] == False:
			flash(["error", "You are not login"], "danger")
			resp = make_response(redirect(url_for("spell_check")))
			return resp
		# current_query = Query.query.filter_by(qid=qid, uid=session["uid"]).all()
		if session["ifAdmin"] != True:
			current_query = Query.query\
													.join(User, User.uid == Query.uid)\
													.add_columns(Query.qid, Query.uid, User.username, Query.qtext, Query.qresult)\
													.filter((Query.qid == qid) & (Query.uid == session["uid"]))\
													.first()
		else:
			current_query = Query.query\
													.join(User, User.uid == Query.uid)\
													.add_columns(Query.qid, Query.uid, User.username, Query.qtext, Query.qresult)\
													.filter(Query.qid == qid)\
													.first()
		resp = make_response(render_template("./query.html", query=current_query))
		return resp


	# Login History
	@app.route(ROOT_URL + '/login_history', methods=['GET', 'POST'])
	def login_history():
		if "ifAdmin" not in session or session["ifAdmin"] == False:
			flash(["error", "You are not login as an admin"], "danger")
			resp = make_response(redirect(url_for("spell_check")))
			return resp

		form = AdminLoginLogQueryForm()
		if form.validate_on_submit():
			uid = form.userid.data
			
			records = User.query\
					.join(LoginLog, User.uid == LoginLog.uid)\
					.add_columns(LoginLog.rid, User.uid, User.username, LoginLog.loginTime, LoginLog.logoutTime)\
					.filter(User.uid == uid)\
					.order_by(LoginLog.rid)\
					.all()

			resp = make_response(render_template("./loginhistory.html", form=form, records=records))
			return resp
		else:
			resp = make_response(render_template("./loginhistory.html", form=form))
			return resp


	# Utils
	def register_with_user_info(username, password, phone):
		"""
		return ifRegisterSuccess: bool, errorMessage: string
		"""
		password = generate_password_hash(password)
		# Check whether username already existed
		existing_user = User.query.filter_by(username=username).first()

		# if username in USER_DATABASE.keys():
		if existing_user is not None:
			# Given username has been already registered
			return (False, "failure")
		else:
			new_user = User(
				username=username,
				password=password,
				phone=phone
			)
			db.session.add(new_user)
			db.session.commit()
			# USER_DATABASE[username] = {
			# 	"password": password,
			# 	"phone": phone
			# }
			return (True, "success")


	def login_with_user_info(username, password, phone):
		"""
		return ifLoginSuccess: bool, errorMessage: string
		"""

		existing_user = User.query.filter_by(username=username).first()

		# if username not in USER_DATABASE.keys():
		if existing_user is None:
			return (False, "Incorrect")
		else:
			password = generate_password_hash(password)
			# if password != USER_DATABASE[username]["password"]:
			# if check_password_hash(password, USER_DATABASE[username]["password"]):
			if check_password_hash(password, existing_user.password):
				return (False, "Incorrect")
			# elif phone != USER_DATABASE[username]["phone"]:
			elif phone != existing_user.phone:
				return (False, "Two-factor failure")
			else:
				session["username"] = existing_user.username
				session["ifAdmin"] = existing_user.ifAdmin
				session["uid"] = existing_user.uid
				return (True, "Login success")


	def gen_random_string(num):
		return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(num))


	def gen_random_filename():
		_f = gen_random_string(16)
		return "tmp_" + base64.urlsafe_b64encode(hashlib.md5(_f.encode()).digest()).decode()


	def check_text_spelling(content):
		_tmp_filename = gen_random_filename()
		with open(_tmp_filename, "w") as fp:
			fp.write(content)
		proc = subprocess.Popen("./spell-check/a.out ./{} ./spell-check/wordlist.txt".format(_tmp_filename), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = proc.communicate()
		if err == b'':
			out = out.decode().replace('\n', ',')
		else:
			pass
		subprocess.call("rm -rf ./{}".format(_tmp_filename), shell=True)
		return out


# Create Flask app as a global variable.
# This enables app to be executed by command:
#   - export FLASK_APP=app.py
#   - flask run
app = Flask(__name__, template_folder="./templates")
app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKey"
app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"
# Random secret_key does work, but this will lose all existed sessions
# when current flask application restarts.
# app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
# app.WTF_CSRF_SECRET_KEY = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))

app.config.update(
	SQLALCHEMY_DATABASE_URI='sqlite:///sqlite3/cs9163.sqlite3'
)

app.config.update(
	SESSION_COOKIE_HTTPONLY=True,
	SESSION_COOKIE_SAMESITE='Lax',
	PERMANENT_SESSION_LIFETIME=600
)
csrf = CSRFProtect(app)
paranoid = Paranoid(app)
configure_routes(app)
paranoid.redirect_view = ROOT_URL + '/login'

if __name__ == "__main__":
	app.run(debug=True)
