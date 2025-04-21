from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(200))
    preferred_mode = db.Column(db.String(50))  
    address = db.Column(db.String(200))
    blood_group = db.Column(db.String(10))
    nid = db.Column(db.String(30))
    profile_picture = db.Column(db.String(120), default='default.jpg')
    is_approved = db.Column(db.Boolean, default=False)
    id_document = db.Column(db.String(100))
    verified = db.Column(db.Boolean, default=False)
    home_location = db.Column(db.String(255))
    frequent_routes = db.Column(db.Text)
    safety_preference = db.Column(db.String(100))


class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    


class RidePost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_location = db.Column(db.String(150), nullable=False)
    to_location = db.Column(db.String(150), nullable=False)
    travel_date = db.Column(db.Date, nullable=False)
    travel_time = db.Column(db.Time, nullable=False)
    seats_available = db.Column(db.Integer, nullable=False)
    fare_type = db.Column(db.String(50), nullable=False)  # 'fare-sharing', 'free', 'safety'
    estimated_cost = db.Column(db.Float)  # optional for fare-sharing
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RideRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ride_id = db.Column(db.Integer, db.ForeignKey('ride_post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(300))
    status = db.Column(db.String(50), default='pending')  # pending, accepted, rejected
    request_time = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    __tablename__ = 'feedbacks'
    
    feedback_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ride_id = db.Column(db.Integer, db.ForeignKey('ride_post.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
