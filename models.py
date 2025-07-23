from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# ===============================
# Course Model
# ===============================
class Course(db.Model):
    __tablename__ = 'courses'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)

    # One-to-Many: Course → Chapters
    chapters = db.relationship(
        'Chapter',
        backref='course',
        cascade='all, delete-orphan',
        lazy=True
    )

# ===============================
# Chapter Model
# ===============================
class Chapter(db.Model):
    __tablename__ = 'chapters'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)

    # One-to-Many: Chapter → Videos
    videos = db.relationship(
        'Video',
        backref='chapter',
        cascade='all, delete-orphan',
        lazy=True
    )

# ===============================
# Video Model
# ===============================
class Video(db.Model):
    __tablename__ = 'videos'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapters.id'), nullable=False)
