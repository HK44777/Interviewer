from flask import Flask, render_template, flash, url_for, redirect, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DateField, TimeField, IntegerRangeField, SelectField, TextAreaField,FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['SECRET_KEY'] = "123456789"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///interview.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id             = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name           = db.Column(db.String(50), nullable=False)
    email          = db.Column(db.String(120), unique=True, nullable=False)
    password_hash  = db.Column(db.String(128), nullable=False)
    pdf_data       = db.Column(db.LargeBinary, nullable=True)
    pdf_filename   = db.Column(db.String(260), nullable=True)
    jobdesc_data         = db.Column(db.LargeBinary, nullable=True)
    jobdesc_filename     = db.Column(db.String(260), nullable=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SignUpForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired(),Length(min=8)])
    confirm_password=PasswordField("Confirm Password", validators=[DataRequired(),EqualTo('password', message="Passwords must match.")])
    resume = FileField('Upload PDF Document',
                       validators=[
                           FileRequired(message="Please upload a PDF file."),
                           FileAllowed(['pdf'], message="Only PDF files are allowed.")])
    submit = SubmitField("Submit")

class JobDescForm(FlaskForm):
    jobdesc = FileField(
        'Upload Job Description (PDF)',
        validators=[
            FileRequired(message="Please upload a PDF file."),
            FileAllowed(['pdf'],    message="Only PDF files are allowed.")
        ]
    )
    submit = SubmitField("Proceed")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired(),Length(min=8)])
    submit = SubmitField("Login")

with app.app_context():
    db.create_all()


# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        # 1. Prevent duplicate emails
        if User.query.filter_by(email=form.email.data).first():
            flash("Email is already registered.", 'danger')
            return render_template('sign_up.html', form=form)

        # 2. Read and secure the uploaded PDF
        file_obj = form.resume.data            # sanitize filename
        file_bytes = file_obj.read()                   # raw bytes for BLOB

        # 3. Create the new user, including resume data
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            pdf_data =file_bytes,
            pdf_filename=file_obj.filename
        )
        new_user.set_password(form.password.data)      # hash & store password

        # 4. Persist to database
        db.session.add(new_user)
        db.session.commit()

        # 5. Log in and redirect
        login_user(new_user)
        flash("Account created successfully!", 'success')
        return redirect(url_for('main'))

    return render_template('sign_up.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Check if the password is correct
            if user.check_password(form.password.data):
                login_user(user)
                return redirect(url_for('main'))
            else:
                # Wrong password
                flash("Incorrect password. Please try again.", 'danger')
        else:   
            # Account does not exist
            flash("No account found with this email. Please sign up first.", 'warning')
    
    return render_template('login.html', form=form)

@app.route('/main', methods=['GET', 'POST'])
@login_required
def main():
    form = JobDescForm()
    # If we detect a POST (modal form submission), handle it here:
    if form.validate_on_submit():
        file_obj   = form.jobdesc.data
        file_bytes = file_obj.read()
        current_user.jobdesc_data     = file_bytes
        current_user.jobdesc_filename = file_obj.filename
        db.session.commit()
        flash("Job description uploaded! Starting interview…", 'success')
        return redirect(url_for('interview'))
    return render_template('main.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
