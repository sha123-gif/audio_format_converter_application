from flask import Flask, render_template, request, flash, send_from_directory, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from pydub import AudioSegment
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'mp3', 'wav', 'ogg'}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the User model for SQLAlchemy
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Define forms using Flask-WTF
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Reset Password')

class UploadForm(FlaskForm):
    file = FileField('Audio File', validators=[DataRequired()])
    format = SelectField('Format', choices=[('mp3', 'MP3'), ('wav', 'WAV'), ('ogg', 'OGG')], validators=[DataRequired()])
    submit = SubmitField('Upload & Convert')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for registering a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route for logging in a user
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

# Route for resetting password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email address not found. Please enter a valid email.', 'danger')
    return render_template('forgot_password.html', form=form)

# Route for logging out a user
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Route for home page after login
@app.route('/')
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Route for uploading and converting audio files
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        audio_file = form.file.data
        if audio_file and allowed_file(audio_file.filename):
            filename = secure_filename(audio_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            audio_file.save(file_path)
            
            # Conversion logic (dummy example)
            if form.format.data == 'mp3':
                converted_format = 'mp3'
            elif form.format.data == 'wav':
                converted_format = 'wav'
            elif form.format.data == 'ogg':
                converted_format = 'ogg'
            
            # Dummy conversion (replace with actual conversion logic)
            audio = AudioSegment.from_file(file_path)
            converted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{os.path.splitext(filename)[0]}.{converted_format}")
            audio.export(converted_file_path, format=converted_format)
            
            flash('File successfully uploaded and converted', 'success')
            return send_from_directory(app.config['UPLOAD_FOLDER'], f"{os.path.splitext(filename)[0]}.{converted_format}", as_attachment=True)
        else:
            flash('Invalid file format. Allowed formats are MP3, WAV, and OGG.', 'danger')
    return render_template('upload.html', form=form)

# Route for serving uploaded files
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Main entry point of the application
if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('site.db'):
            db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
