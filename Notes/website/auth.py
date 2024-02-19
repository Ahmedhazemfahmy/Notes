from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db 
from flask_login import login_required, login_user, logout_user, current_user

auth = Blueprint('auth', __name__)

def generate_password_hash(password):
    # You can use a secure password hashing library like bcrypt in a real-world scenario
    # For simplicity, let's just concatenate 'hashed_' to the password
    return 'hashed_' + password

def check_password_hash(hashed_password, password):
    # For simplicity, let's just check if the hashed_password starts with 'hashed_'
    return hashed_password.startswith('hashed_' + password)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Logged in successfully.', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.home'))
        else:
            flash('Incorrect email or password. Please try again.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstname')  # Corrected form field name
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Use existing_user instead of user
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email in use', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif first_name and len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')

        elif password1 != password2:
            flash('Mismatched passwords', category='error')
        elif len(password1) < 7:
            flash('Password must be greater than 6 characters', category='error')
        else:
            hashed_password = generate_password_hash(password1)
            new_user = User(email=email, first_name=first_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            # Use the newly created user for login instead of the existing_user
            login_user(new_user, remember=True)
            
            flash('Account Created', category='success')
            return redirect(url_for('views.home'))
        
    return render_template("sign_up.html", user=current_user)
