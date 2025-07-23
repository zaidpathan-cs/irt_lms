from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    chapters = db.relationship('Chapter', backref='course', cascade="all, delete-orphan", lazy=True)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    videos = db.relationship('Video', backref='chapter', cascade="all, delete-orphan", lazy=True)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('home_page'))

@app.route('/home')
def home_page():
    featured_courses = Course.query.limit(3).all()
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
        role = request.form.get('role', 'student')

        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('register'))
        
        if len(username) < 4:
            flash('Username must be at least 4 characters', 'error')
            return redirect(url_for('register'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        try:
            new_user = User(username=username, role=role)
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home_page'))

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# Sample Data
@app.route('/add-sample-data')
def add_sample_data():
    if Course.query.count() == 0:
        # Create sample courses
        python_course = Course(
            title="Python Basics",
            description="Learn Python programming fundamentals"
        )
        
        web_course = Course(
            title="Web Development",
            description="Learn HTML, CSS, and JavaScript"
        )
        
        data_course = Course(
            title="Data Science",
            description="Introduction to data analysis and visualization"
        )
        
        # Create sample chapters
        python_chapter1 = Chapter(title="Introduction to Python", course=python_course)
        python_chapter2 = Chapter(title="Python Syntax", course=python_course)
        
        web_chapter1 = Chapter(title="HTML Basics", course=web_course)
        web_chapter2 = Chapter(title="CSS Styling", course=web_course)
        
        data_chapter1 = Chapter(title="Pandas Basics", course=data_course)
        
        # Create sample videos
        python_video1 = Video(title="What is Python?", url="/static/sample.mp4", chapter=python_chapter1)
        python_video2 = Video(title="Variables and Data Types", url="/static/sample.mp4", chapter=python_chapter1)
        
        web_video1 = Video(title="HTML Structure", url="/static/sample.mp4", chapter=web_chapter1)
        
        data_video1 = Video(title="Pandas Introduction", url="/static/sample.mp4", chapter=data_chapter1)
        
        # Create sample users
        student1 = User(username="student1", role="student")
        student1.set_password("password123")
        
        instructor1 = User(username="instructor1", role="instructor")
        instructor1.set_password("password123")
        
        db.session.add_all([
            python_course, web_course, data_course,
            python_chapter1, python_chapter2, 
            web_chapter1, web_chapter2,
            data_chapter1,
            python_video1, python_video2,
            web_video1,
            data_video1,
            student1, instructor1
        ])
        db.session.commit()
        return "✅ Sample data added!"
    return "⚠️ Sample data already exists."

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)