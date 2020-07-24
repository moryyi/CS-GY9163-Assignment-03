from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class User(db.Model):
  __tablename__ = 'Users'
  __table_args__ = { 'extend_existing': True }
  uid = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(30), unique=True, nullable=False)
  password = db.Column(db.String(120), unique=True, nullable=False)
  phone = db.Column(db.String(30), unique=True, nullable=False)
  ifAdmin = db.Column(db.Boolean, nullable=False, default=False)

  def __repr__(self):
    return '<User {}>'.format(self.username)


class Query(db.Model):
  __tablename__ = 'Queries'
  __table_args__ = { 'extend_existing': True}
  qid = db.Column(db.Integer, primary_key=True)
  uid = db.Column(db.Integer, db.ForeignKey('Users.uid'), nullable=False)
  qtext = db.Column(db.String(1000), nullable=False)
  qresult = db.Column(db.String(1001), nullable=False)


class LoginLog(db.Model):
  __tablename__ = 'Logs'
  __table_args__ = { 'extend_existing': True }
  rid = db.Column(db.Integer, primary_key=True)
  uid = db.Column(db.Integer, db.ForeignKey('Users.uid'), nullable=False)
  loginTime = db.Column(db.DateTime, default=datetime.datetime.utcnow)
  logoutTime = db.Column(db.DateTime, default=None, onupdate=datetime.datetime.utcnow())
