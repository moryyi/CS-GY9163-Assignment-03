#!/usr/bin/python3
# coding: utf-8

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from src.app import configure_routes

ROOT_URL = "/cs9163/hw02"

def test_home_route():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  app.testing = True
  configure_routes(app)
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/"
  response = client.get(url, follow_redirects=True)
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"uname" in response.data
  assert b"pword" in response.data
  assert b"2fa" in response.data


def test_login_get():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  app.testing = True
  configure_routes(app)
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/login"
  response = client.get(url)
  assert response.status_code == 200
  assert b"Login" in response.data
  assert b"uname" in response.data
  assert b"pword" in response.data
  assert b"2fa" in response.data


def test_register_get():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  app.testing = True
  configure_routes(app)
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/register"
  response = client.get(url)
  assert response.status_code == 200
  assert b"Register" in response.data
  assert b"uname" in response.data
  assert b"pword" in response.data
  assert b"2fa" in response.data

  
def test_spell_get():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  app.WTF_CSRF_SECRET_KEY = "CS9163Assignment02WebsiteFlaskWTFCSRFToken"

  app.testing = True
  configure_routes(app)
  csrf = CSRFProtect(app)
  client = app.test_client()

  url = ROOT_URL + "/spell_check"
  response = client.get(url, follow_redirects=True)
  assert response.status_code == 200
  assert b"Register" in response.data
  assert b"uname" in response.data
  assert b"pword" in response.data
  assert b"2fa" in response.data