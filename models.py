from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import Float

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
    average_rating = db.Column(db.Float, default=0.0)
    total_ratings = db.Column(db.Integer, default=0)
    gender = db.Column(db.String(10))  # male, female, other

class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    


# models.py

class RidePost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # ✅ Foreign key
    creator = db.relationship('User', backref='ride_posts')       # ✅ Relationship

    from_location = db.Column(db.String(150), nullable=False)
    to_location = db.Column(db.String(150), nullable=False)
    travel_date = db.Column(db.Date, nullable=False)
    travel_time = db.Column(db.Time, nullable=False)
    seats_available = db.Column(db.Integer, nullable=False)
    fare_type = db.Column(db.String(50), nullable=False)
    estimated_cost = db.Column(db.Float)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # In RidePost model
    gender_preference = db.Column(db.String(20), default='any')  # any, female_only
    require_verification = db.Column(db.Boolean, default=False)  # Require verified users only
    from_lat = db.Column(Float)
    from_lng = db.Column(Float)
    to_lat = db.Column(Float)
    to_lng = db.Column(Float)
    ride_requests = db.relationship('RideRequest', backref='ride_post', cascade='all, delete-orphan')
    




class RideRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ride_id = db.Column(db.Integer, db.ForeignKey('ride_post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')  # ✅ Add this line
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
# models.py

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_type = db.Column(db.String(10), default='user')  # 'user' or 'admin'S
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ride_id = db.Column(db.Integer, db.ForeignKey('ride_post.id'), nullable=True)  # ✅ Link to RidePost
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    

    recipient = db.relationship('User', foreign_keys=[recipient_id])
    sender = db.relationship('User', foreign_keys=[sender_id])
    ride = db.relationship('RidePost', backref='notifications')

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ride_id = db.Column(db.Integer, db.ForeignKey('ride_post.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])
    ride = db.relationship('RidePost')

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship('Message', backref='chat', lazy=True)
    
    # 💬 These two lines fix your problem
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

    

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class DeletedRide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_ride_id = db.Column(db.Integer, nullable=False)
    creator_id = db.Column(db.Integer, nullable=False)
    origin = db.Column(db.String(100))
    destination = db.Column(db.String(100))
    travel_date = db.Column(db.Date)
    travel_time = db.Column(db.Time)
    fare = db.Column(db.Float)
    seats = db.Column(db.Integer)
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    deleted_by_admin_id = db.Column(db.Integer)  # optional

    # Optional: relationship back to creator
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref='deleted_rides')
