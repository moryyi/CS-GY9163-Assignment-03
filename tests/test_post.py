#!/usr/bin/python3
# coding: utf-8

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask.testing import FlaskClient as BaseFlaskClient

from src.app import configure_routes

ROOT_URL = "/cs9163/hw02/pytest"

def test_login_without_register_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  app.testing = True
  csrf = CSRFProtect(app)
  configure_routes(app, csrf)
  client = app.test_client()

  url = ROOT_URL + "/login"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  assert response.status_code == 200
  assert b"result" in response.data
  assert b"Incorrect" in response.data


def test_first_register_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"
  
  configure_routes(app)
  app.testing = True
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/register"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"success" in response.data


def test_existed_register_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  configure_routes(app)
  app.testing = True
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/register"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  assert response.status_code == 200
  assert b"Register" in response.data
  assert b"failure" in response.data


def test_login_with_correct_data_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  configure_routes(app)
  app.testing = True
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/register"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  url = ROOT_URL + "/login"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"Login success" in response.data


def test_multiple_login_with_correct_data_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  configure_routes(app)
  app.testing = True
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/register"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  url = ROOT_URL + "/login"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
  url = ROOT_URL + "/login"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
  assert response.status_code == 200
  assert b"already logged in" in response.data


def test_login_with_incorrect_data_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  configure_routes(app)
  app.testing = True
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/register"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
  url = ROOT_URL + "/login"
  response = client.post(url, data={"uname": "wrongusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"Incorrect" in response.data

  response = client.post(url, data={"uname": "testusername", "pword": "wrongpassword", "2fa": "testnumber"}, follow_redirects=True)
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"Incorrect" in response.data

  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "wrongnumber"}, follow_redirects=True)
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"Two-factor failure" in response.data