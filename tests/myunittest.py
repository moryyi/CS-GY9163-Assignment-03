#!/usr/bin/python3
# coding: utf-8


from flask import Flask
from flask_testing import TestCase
import unittest

from src.app import configure_routes

ROOT_URL = "/cs9163/hw02"

class MyTest(TestCase):
  def create_app(self):
    app = Flask(__name__, template_folder="../src/templates/")
    app.secret_key = "CS9163Assignment02WebsiteFlaskSessionSecretKeyForPytestOnly"
    configure_routes(app)
    app.config["TESTING"] = True
    app.config["DEBUG"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    return app
  
  def tearDown(self):
    pass
  

  # Testcases
  def test_login_get(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/login"
    response = client.get(url)
    assert response.status_code == 200
    assert b"Login" in response.data
    assert b"uname" in response.data
    assert b"pword" in response.data
    assert b"2fa" in response.data


  def test_register_get(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.get(url)
    assert response.status_code == 200
    assert b"Register" in response.data
    assert b"uname" in response.data
    assert b"pword" in response.data
    assert b"2fa" in response.data

    
  def test_spell_get(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/spell_check"
    response = client.get(url, follow_redirects=True)
    assert response.status_code == 200
    assert b"Register" in response.data
    assert b"uname" in response.data
    assert b"pword" in response.data
    assert b"2fa" in response.data

  def test_login_without_register_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/login"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    assert response.status_code == 200


  def test_first_register_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    assert response.status_code == 200


  def test_existed_register_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    assert response.status_code == 200


  def test_login_with_correct_data_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    url = ROOT_URL + "/login"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
    assert response.status_code == 200


  def test_multiple_login_with_correct_data_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    url = ROOT_URL + "/login"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
    url = ROOT_URL + "/login"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
    assert response.status_code == 200


  def test_login_with_incorrect_data_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})
    url = ROOT_URL + "/login"
    response = client.post(url, data={"uname": "wrongusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
    assert response.status_code == 200

    response = client.post(url, data={"uname": "testusername", "pword": "wrongpassword", "2fa": "testnumber"}, follow_redirects=True)
    assert response.status_code == 200

    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "wrongnumber"}, follow_redirects=True)
    assert response.status_code == 200

  def test_spell_with_login_post(self):
    app = self.create_app()
    client = app.test_client()

    url = ROOT_URL + "/register"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"})

    url = ROOT_URL + "/login"
    response = client.post(url, data={"uname": "testusername", "pword": "testpassword", "2fa": "testnumber"}, follow_redirects=True)
    
    url = ROOT_URL + "/spell_check"
    text2check = "Take a sad sogn and make it better. Remember to let her under your (skyn),.! then you b3gin to make it betta."
    response = client.post(url, data={"inputtext": text2check})
    assert response.status_code == 200

if __name__ == "__main__":
  unittest.main()