#!/usr/bin/python3
# coding: utf-8

from flask import Flask, g, current_app
import pytest
from flask_wtf.csrf import CSRFProtect, generate_csrf

from src.app import configure_routes
from src.myForms import LoginForm, RegisterForm, ContentForm

ROOT_URL = "/cs9163/hw02"


def test_spell_with_login_post():
  app = Flask(__name__, template_folder='../src/templates')
  app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
  configure_routes(app)
  app.config["TESTING"] = True
  app.config["DEBUG"] = False
  app.config["WTF_CSRF_ENABLED"] = False
  client = app.test_client()

  form = RegisterForm(
    username="testusername",
    password="testpassword",
    phone="testnumber"
  )
  url = ROOT_URL + "/register"
  response = client.post(url, data=form.data)

  url = ROOT_URL + "/login"
  response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)

  url = ROOT_URL + "/spell_check"
  text2check = "Take a sad sogn and make it better. Remember to let her under your (skyn),.! then you b3gin to make it betta."
  response = client.post(url, data={"inputtext": text2check})

  assert response.status_code == 200
  assert b"textout" in response.data
  assert b"misspelled" in response.data