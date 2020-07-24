from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import DataRequired


class RegisterForm(FlaskForm):
	username = StringField(id="uname", validators=[DataRequired()],
													render_kw={'placeholder': 'Username'})
	password = PasswordField(id="pword", validators=[DataRequired()],
													render_kw={'placeholder': 'Password'})
	phone = StringField(id="2fa", validators=[DataRequired()],
													render_kw={'placeholder': 'Cell Phone Number'})
	submit = SubmitField("submit")

class LoginForm(FlaskForm):
	username = StringField(id="uname", validators=[DataRequired()],
													render_kw={'placeholder': 'Username'})
	password = PasswordField(id="pword", validators=[DataRequired()],
													render_kw={'placeholder': 'Password'})
	phone = StringField(id="2fa", validators=[DataRequired()],
													render_kw={'placeholder': 'Cell Phone Number'})
	login = SubmitField("login")

class ContentForm(FlaskForm):
  inputtext = TextAreaField(id="inputtext", validators=[DataRequired()],
                          render_kw={'placeholder': 'Text to check spelling', 'aria-label': 'With textarea'})
  submit = SubmitField("check")

class AdminLoginLogQueryForm(FlaskForm):
  userid = IntegerField(id="userid", validators=[DataRequired()],
                          render_kw={'placeholder': 'uid of User to be checked'})
  submit = SubmitField("search")

class AdminQueryCheckForm(FlaskForm):
  userquery = StringField(id="userquery",
                          render_kw={'placeholder': 'username to be checked queries'})
  submit = SubmitField("search")
