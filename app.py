from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Admin
import config
from flask import Flask, request, jsonify, session
from models import db, RidePost, User, RideRequest, Feedback
from datetime import time
import os
from werkzeug.utils import secure_filename



from flask_migrate import Migrate


app = Flask(__name__)
app.config.from_object(config)

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/profile_pics')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
upload_path = os.path.join(app.config['UPLOAD_FOLDER'])
if not os.path.exists(upload_path):
    os.makedirs(upload_path)



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'warning')
            return redirect(url_for('register'))

        new_user = User(name=name, email=email, phone=phone, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name, user=current_user)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        current_user.preferred_mode = request.form['preferred_mode']
        current_user.address = request.form['address']
        current_user.nid = request.form['nid']
        current_user.blood_group = request.form['blood_group']

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '':
                filename = secure_filename(file.filename)

                # Make sure the folder exists
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'])
                if not os.path.exists(upload_path):
                    os.makedirs(upload_path)

                filepath = os.path.join(upload_path, filename)
                file.save(filepath)
                current_user.profile_picture = filename
        if 'id_document' in request.files:
            doc = request.files['id_document']
            if doc and doc.filename:
                filename = secure_filename(doc.filename)
                doc_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                doc.save(doc_path)
                current_user.id_document = filename


        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('profile.html')

@app.route('/preferences', methods=['GET', 'POST'])
@login_required
def preferences():
    if request.method == 'POST':
        current_user.home_location = request.form['home_location']
        current_user.frequent_routes = request.form['frequent_routes']
        current_user.safety_preference = request.form['safety_preference']
        db.session.commit()
        flash('Preferences updated successfully!', 'success')
        return redirect(url_for('preferences'))
    
    return render_template('preferences.html', user=current_user)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_logged_in'] = True
            session['admin_id'] = admin.id
            return redirect(url_for('admin_dashboard'))
        flash("Invalid admin credentials", "danger")
    return render_template('admin_login.html')
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
def view_users():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    users = User.query.order_by(User.id.desc()).all()
    return render_template('view_users.html', users=users)

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
def verify_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    user = User.query.get_or_404(user_id)
    user.verified = True
    db.session.commit()
    flash('User verified successfully!', 'success')
    return redirect(url_for('view_users'))

@app.route('/admin/approve/<int:user_id>')
def approve_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash('User approved successfully!', 'success')
    return redirect(url_for('view_users'))

@app.route('/admin/restrict/<int:user_id>')
def restrict_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    user = User.query.get_or_404(user_id)
    user.is_approved = False
    db.session.commit()
    flash('User restricted successfully!', 'warning')
    return redirect(url_for('view_users'))

@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('view_users'))

@app.route('/admin_logout')
def admin_logout():
    session.clear()  # clears everything, both user and admin
    flash('Logged out successfully.', 'success')
    return redirect(url_for('admin_login'))




@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
