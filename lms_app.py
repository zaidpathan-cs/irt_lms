from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ========== MODELS ==========
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
    is_published = db.Column(db.Boolean, default=False)
    thumbnail_url = db.Column(db.String(255))
    difficulty_level = db.Column(db.String(20), default='beginner')
    category = db.Column(db.String(50))

    chapters = db.relationship('Chapter', backref='course', cascade='all, delete-orphan', lazy=True)
    enrollments = db.relationship('Enrollment', back_populates='course', cascade='all, delete-orphan')

class Chapter(db.Model):
    __tablename__ = 'chapters'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    sequence = db.Column(db.Integer, nullable=False, default=0)
    is_free_preview = db.Column(db.Boolean, default=False)

    videos = db.relationship('Video', backref='chapter', cascade='all, delete-orphan', lazy=True)

class Video(db.Model):
    __tablename__ = 'videos'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(255), nullable=False)
    thumbnail_url = db.Column(db.String(255))
    duration = db.Column(db.Integer)  # in seconds
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapters.id'), nullable=False)
    sequence = db.Column(db.Integer, nullable=False, default=0)
    is_preview = db.Column(db.Boolean, default=False)

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)  # percentage
    
    user = db.relationship('User', back_populates='enrollments')
    course = db.relationship('Course', back_populates='enrollments')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'course_id', name='unique_enrollment'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== ROUTES ==========
@app.route('/')
def home():
    return redirect(url_for('home_page'))

@app.route('/home')
def home_page():
    featured_courses = Course.query.filter_by(is_published=True).limit(3).all()
    return render_template('home.html', featured_courses=featured_courses, current_year=datetime.now().year)

@app.route('/about')
def about():
    return render_template('about.html', current_year=datetime.now().year)

@app.route('/courses')
def list_courses():
    courses = Course.query.all()
    return render_template('courses.html', courses=courses, current_year=datetime.now().year)

@app.route('/course/<int:course_id>')
def view_course(course_id):
    course = Course.query.get_or_404(course_id)
    return render_template('course.html', course=course, current_year=datetime.now().year)

@app.route('/chapter/<int:chapter_id>')
def view_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    return render_template('chapter.html', chapter=chapter, current_year=datetime.now().year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', current_year=datetime.now().year)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        role = request.form.get('role', 'student')

        # Validation
        errors = []
        if not all([username, password, email, name]):
            errors.append('All fields are required except phone')
        if len(username) < 4:
            errors.append('Username must be at least 4 characters')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append('Invalid email format')
        if phone and not re.match(r"^\+?[0-9]{10,15}$", phone):
            errors.append('Phone must be 10-15 digits, optionally starting with +')
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered')

        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('register'))

        try:
            new_user = User(
                username=username,
                email=email,
                name=name,
                phone=phone,
                role=role
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html', current_year=datetime.now().year)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user, current_year=datetime.now().year)

@app.route('/profile')
@login_required
def profile():
    enrolled_courses = Enrollment.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', 
                         user=current_user, 
                         enrolled_courses=enrolled_courses,
                         current_year=datetime.now().year)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home_page'))

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'instructor':
        abort(403)
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
