# CS-GY9163-Assignment-02

[![Build Status](https://travis-ci.org/qb1ng/CS-GY9163-Assignment-02.svg?branch=master)](https://travis-ci.org/qb1ng/CS-GY9163-Assignment-02)

Repo for CS9163 Assignment 02

## Spell-Check Website
This website is developed with Flask, Python3, and Bootstrap.

Register, login into the website, and submit text for spell-checking.

## Install required dependencies
- Install requirements with pip

  ```sh
  pip install -r requirements.txt
  ```
  
## Test with unittest
- To test the service with *unittest*, execute the script in *./tests/myunittest.py*

  ```sh
  python ./tests/myunittest.py
  ```

## Start the service
- To start this Flask application
  ```sh
  chmod +x app.py
  ./app.py
  ```

  or with Flask command (tested in Ubuntu VM):
  ```sh
  cd src/
  export FLASK_APP=app.py
  flask run
  ```

## How to use
1. Open the browser and enter URL http://127.0.0.1:5000/cs9163/hw02/
2. The URLs available are:
   1. home: http://127.0.0.1:5000/cs9163/hw02/ &larr; redirect to login page
   2. login: http://127.0.0.1:5000/cs9163/hw02/login
   3. register: http://127.0.0.1:5000/cs9163/hw02/register
   4. spell check: http://127.0.0.1:5000/cs9163/hw02/spell_check &larr; require user login

## About testing
This assignment project has switched from *pytest* to *unittest*.

One of the most important reasons for this is that, by using *pytest*, it is difficult to perform testing along with CSRF protection, provided by **flask_wtf**.

Besides, when using *unittest*, `app.config["WTF_CSRF_ENABLED"] = False` can successfully turn off CSRF protection in order to simply check whether these routes are reachable. But this config setting doesn't work when using *pytest*.

In brief, testcases in this project only perform without CSRF protection and only check whether the requests and responses are successfully sent and received.

## Others
Some of the source codes are learnt from this Flask project Tutorial [Youtube Video](https://www.youtube.com/watch?v=d04xxdrc7Yw).
