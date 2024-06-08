from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy import Integer, String, select
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bootstrap import Bootstrap5
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_wtf import FlaskForm

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)

Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100))


class RegisterForm(FlaskForm):
    new_name = StringField(validators=[DataRequired()], render_kw={"placeholder": "Name"}, label="")
    new_email = StringField(validators=[DataRequired()], render_kw={"placeholder": "Email"}, label="")
    new_pw = PasswordField(validators=[DataRequired()], render_kw={"placeholder": "Password"}, label="")
    submit = SubmitField("Sign Me Up")

class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()], render_kw={"placeholder": "Email"}, label="")
    password = PasswordField(validators=[DataRequired()], render_kw={"placeholder": "Password"}, label="")
    submit = SubmitField("Let Me In")


@login_manager.user_loader
def load_user(id):
    return    User.query.get(int(id))

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_active)

@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        with Session(app):
            user = db.session.execute(select(User).where(User.email == register_form.new_email.data)).scalar()
            if user == None:
                hashed_pw = generate_password_hash(
                    method="pbkdf2:sha256:600000", salt_length=8, password=register_form.new_pw.data)
                new_user = User(name=register_form.new_name.data,
                                email=register_form.new_email.data,
                                password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('secrets'))
            else:
                flash("User already exists.")
    return render_template("register.html", form=register_form, logged_in=current_user.is_active)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        with Session(app):
            user = db.session.execute(select(User).where(User.email == email)).scalar()
            if user:
                if check_password_hash(pwhash=user.password, password=login_form.password.data):
                    login_user(user)
                    return redirect(url_for('secrets'))
                else: flash("Incorrect password.")
            else: flash("User does not exist.")
    return render_template("login.html", form=login_form, logged_in=current_user.is_active)


@app.route('/secrets')
@login_required
def secrets():
        return render_template(
            "secrets.html", name=current_user.name,logged_in=current_user.is_active)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
            return send_from_directory("static/files", "cheat_sheet.pdf", as_attachment=True)



if __name__ == "__main__":
    app.run(debug=True)