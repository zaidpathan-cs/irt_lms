from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pictures'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ======================= MODELS =======================
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    profile_picture = db.Column(db.String(255))

    courses_created = db.relationship('Course', backref='instructor', lazy=True)
    enrollments = db.relationship('Enrollment', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    short_description = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    instructor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_published = db.Column(db.Boolean, default=True)
    thumbnail_url = db.Column(db.String(255))
    difficulty_level = db.Column(db.String(20), default='beginner')
    category = db.Column(db.String(50))

    enrollments = db.relationship('Enrollment', back_populates='course', cascade='all, delete-orphan')

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)

    user = db.relationship('User', back_populates='enrollments')
    course = db.relationship('Course', back_populates='enrollments')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'course_id', name='unique_enrollment'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======================= HELPERS =======================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ======================= ROUTES =======================

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('profile'))

@app.route('/about')
def about():
    return render_template('about.html', current_year=datetime.now().year)

@app.route('/')
def home_page():
    return redirect(url_for('profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']
        email = request.form['email']
        name = request.form['name']
        phone = request.form['phone']

        if password != confirm:
            flash("Passwords don't match", 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already taken", 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered", 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email, name=name, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please login.", 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    enrolled_courses = Enrollment.query.filter_by(user_id=current_user.id).all()
    created_courses = []
    if current_user.role == 'instructor':
        created_courses = Course.query.filter_by(instructor_id=current_user.id).all()
    return render_template('profile.html', user=current_user, enrolled_courses=enrolled_courses, created_courses=created_courses, current_year=datetime.now().year)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name', current_user.name).strip()
        current_user.email = request.form.get('email', current_user.email).strip()
        current_user.phone = request.form.get('phone', current_user.phone).strip()

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{current_user.id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                if current_user.profile_picture:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture))
                    except:
                        pass
                current_user.profile_picture = filename

        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password and confirm_password:
            if new_password == confirm_password:
                try:
                    current_user.set_password(new_password)
                    flash('Password updated successfully!', 'success')
                except ValueError as e:
                    flash(str(e), 'error')
            else:
                flash('Passwords do not match', 'error')

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'error')

    return render_template('edit_profile.html', user=current_user, current_year=datetime.now().year)

@app.route('/profile/enrolled-courses')
@login_required
def enrolled_courses():
    enrollments = Enrollment.query.filter_by(user_id=current_user.id).join(Course).all()
    return render_template('enrolled_courses.html', enrollments=enrollments, current_year=datetime.now().year)

@app.route('/profile/created-courses')
@login_required
def created_courses():
    if current_user.role != 'instructor':
        abort(403)
    courses = Course.query.filter_by(instructor_id=current_user.id).all()
    return render_template('created_courses.html', courses=courses, current_year=datetime.now().year)

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_profile():
    if not request.form.get('confirm_delete'):
        flash('Please confirm account deletion', 'error')
        return redirect(url_for('edit_profile'))
    try:
        if current_user.profile_picture:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture))
            except:
                pass
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Your account has been deleted successfully', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        flash('Error deleting account. Please try again.', 'error')
        return redirect(url_for('edit_profile'))

# 🔥 NEW ROUTE FOR COURSES PAGE
@app.route('/courses')
@login_required
def list_courses():
    courses = Course.query.filter_by(is_published=True).all()
    return render_template('courses.html', courses=courses, current_year=datetime.now().year)

# ======================= MAIN =======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
