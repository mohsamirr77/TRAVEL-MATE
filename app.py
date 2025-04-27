from flask import Flask, render_template, request, redirect, url_for, flash,abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Admin
import config
from flask import Flask, request, jsonify, session
from models import db, RidePost, User, RideRequest, Feedback, Notification, ChatMessage, Chat, Message
from datetime import time
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, UTC
from sqlalchemy import or_, and_
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
    user_id = current_user.id

    # Upcoming rides created by the user (limit 5)
    upcoming_rides = RidePost.query.filter(
        RidePost.creator_id == user_id,
        RidePost.travel_date >= datetime.today()
    ).order_by(RidePost.travel_date.asc()).limit(5).all()

    # Ride requests made by the user (optional, if needed limit too)
    ride_requests = RideRequest.query.filter(
        RideRequest.user_id == user_id
    ).order_by(RideRequest.request_time.desc()).limit(5).all()

    # Past rides (Travel history) (limit 5)
    travel_history = RidePost.query.filter(
        RidePost.creator_id == user_id,
        RidePost.travel_date < datetime.today()
    ).order_by(RidePost.travel_date.desc()).limit(5).all()

    # Recommended rides (optional, can limit to 5 too)
    recommended_rides = []
    if current_user.frequent_routes:
        route_keywords = [route.strip() for route in current_user.frequent_routes.split(',')]
        recommended_rides = RidePost.query.filter(
            or_(*[RidePost.to_location.ilike(f"%{keyword}%") for keyword in route_keywords]),
            RidePost.creator_id != user_id,
            RidePost.travel_date >= datetime.today()
        ).order_by(RidePost.travel_date.asc()).limit(5).all()

    return render_template('dashboard.html',
                           user=current_user,
                           upcoming_rides=upcoming_rides,
                           ride_requests=ride_requests,
                           travel_history=travel_history,
                           recommended_rides=recommended_rides)

@app.route('/feedback/<int:ride_id>', methods=['GET', 'POST'])
@login_required
def give_feedback(ride_id):
    ride = RidePost.query.get_or_404(ride_id)

    if request.method == 'POST':
        comment = request.form.get('comment')
        rating = request.form.get('rating')  # assume rating is optional

        if not comment:
            flash('Feedback cannot be empty.', 'danger')
            return redirect(request.url)

        # Save feedback (example Feedback model)
        feedback = Feedback(
            ride_id=ride.id,
            user_id=current_user.id,
            comment=comment,
            rating=rating
        )
        db.session.add(feedback)
        db.session.commit()

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('give_feedback.html', ride=ride)

@app.route('/past-journeys')
@login_required
def all_past_journeys():
    user_id = current_user.id

    # Get all past rides
    past_rides = RidePost.query.filter(
        RidePost.creator_id == user_id,
        RidePost.travel_date < datetime.today()
    ).order_by(RidePost.travel_date.desc()).all()

    return render_template('all_past_journeys.html', past_rides=past_rides)

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
@app.route('/create_ride', methods=['GET', 'POST'])
@login_required
def create_ride():
    if request.method == 'POST':
        from_location = request.form['from_location']
        to_location = request.form['to_location']
        travel_date = request.form['travel_date']
        travel_time = request.form['travel_time']
        seats_available = request.form['seats_available']
        fare_type = request.form['fare_type']
        estimated_cost = request.form.get('estimated_cost') or None
        description = request.form.get('description')

        ride = RidePost(
            creator_id=current_user.id,
            from_location=from_location,
            to_location=to_location,
            travel_date=datetime.strptime(travel_date, '%Y-%m-%d'),
            travel_time=datetime.strptime(travel_time, '%H:%M').time(),
            seats_available=int(seats_available),
            fare_type=fare_type,
            estimated_cost=float(estimated_cost) if estimated_cost else None,
            description=description
        )
        db.session.add(ride)
        db.session.commit()
        flash("Ride post created successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('create_ride.html')

@app.route('/ride_posts', methods=['GET'])
@login_required
def ride_posts():
    query = RidePost.query

    # Filters from URL query parameters
    from_location = request.args.get('from_location')
    to_location = request.args.get('to_location')
    fare_type = request.args.get('fare_type')
    travel_date = request.args.get('travel_date')

    if from_location:
        query = query.filter(RidePost.from_location.ilike(f"%{from_location}%"))
    if to_location:
        query = query.filter(RidePost.to_location.ilike(f"%{to_location}%"))
    if fare_type:
        query = query.filter(RidePost.fare_type == fare_type)
    if travel_date:
        try:
            parsed_date = datetime.strptime(travel_date, '%Y-%m-%d').date()
            query = query.filter(RidePost.travel_date == parsed_date)
        except:
            pass

    # Initial unfiltered results
    all_rides = query.order_by(RidePost.created_at.desc()).all()

    # Matching Logic Based on User Preferences
    user_home = current_user.home_location or ""
    user_routes = current_user.frequent_routes.split(",") if current_user.frequent_routes else []
    preferred_fare = current_user.preferred_mode or ""
    today = datetime.now(UTC).date()

    def match_score(ride: RidePost):
        score = 0

        # Location Match (from or to matches home/frequent routes)
        if user_home.lower() in ride.from_location.lower() or user_home.lower() in ride.to_location.lower():
            score += 3
        if any(route.strip().lower() in ride.from_location.lower() or route.strip().lower() in ride.to_location.lower() for route in user_routes):
            score += 3

        # Fare type match
        if ride.fare_type.lower() == preferred_fare.lower():
            score += 2

        # Upcoming ride date match
        if abs((ride.travel_date - today).days) <= 2:
            score += 2

        # Match ride time window (±1 hour of current user's past rides, skipped if no data)
        return score

    # Sort rides by score (desc) + created_at as tiebreaker
    sorted_rides = sorted(all_rides, key=lambda r: (match_score(r), r.created_at), reverse=True)

    return render_template('ride_posts.html', rides=sorted_rides)

@app.route('/chat/<int:chat_id>/messages')
@login_required
def get_chat_messages(chat_id):
    chat = Chat.query.get_or_404(chat_id)
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        return jsonify({'error': 'Unauthorized'}), 403

    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp.asc()).all()

    # Prepare a dictionary to map user ids to their names
    user_map = {
        chat.user1_id: chat.user1.name,
        chat.user2_id: chat.user2.name
    }

    return jsonify({
        'messages': [{
            'sender': 'You' if msg.sender_id == current_user.id else user_map.get(msg.sender_id, 'Unknown'),
            'content': msg.content
        } for msg in messages]
    })
@app.route('/mark_messages_read', methods=['POST'])
@login_required
def mark_messages_read():
    # Mark all unread messages for the current user as read by checking the chat relationships
    unread_messages = Message.query.join(Chat).filter(
        (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id),  # Check if the current user is part of the chat
        Message.is_read == False
    ).all()
    
    for message in unread_messages:
        message.is_read = True
    
    db.session.commit()
    
    return jsonify({'success': True})



@app.route('/chat/start/<int:user_id>', methods=['POST'])
@login_required
def start_chat(user_id):
    # Check if chat already exists between the two users
    existing_chat = Chat.query.filter(
        ((Chat.user1_id == current_user.id) & (Chat.user2_id == user_id)) |
        ((Chat.user1_id == user_id) & (Chat.user2_id == current_user.id))
    ).first()

    if existing_chat:
        return jsonify({'chat_id': existing_chat.id})

    # Otherwise create a new chat
    new_chat = Chat(user1_id=current_user.id, user2_id=user_id)
    db.session.add(new_chat)
    db.session.commit()
    return jsonify({'chat_id': new_chat.id})


@app.route('/chat/<int:chat_id>/send', methods=['POST'])
@login_required
def send_chat_message(chat_id):
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'success': False}), 400

    chat = Chat.query.get_or_404(chat_id)
    if current_user.id not in [chat.user1_id, chat.user2_id]:
        return jsonify({'error': 'Unauthorized'}), 403

    new_message = Message(
        chat_id=chat_id,
        sender_id=current_user.id,
        content=content
    )
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'success': True})

@app.context_processor
def inject_recent_chats():
    if current_user.is_authenticated:
        recent_chats = Chat.query.filter(
            (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id)
        ).order_by(Chat.created_at.desc()).limit(5).all()

        # Attach the other user info
        for chat in recent_chats:
            chat.other_user = chat.user2 if chat.user1_id == current_user.id else chat.user1
    else:
        recent_chats = []
    
    return dict(recent_chats=recent_chats)






@app.route('/request_ride/<int:ride_id>', methods=['POST'])
@login_required
def request_ride(ride_id):
    ride = RidePost.query.get_or_404(ride_id)

    if ride.creator_id == current_user.id:
        flash("You can't request your own ride.", "warning")
        return redirect(url_for('ride_posts'))

    # ❗ Prevent duplicate requests
    existing_request = RideRequest.query.filter_by(ride_id=ride.id, user_id=current_user.id).first()
    if existing_request:
        flash("You have already requested this ride.", "info")
        return redirect(url_for('ride_posts'))

    # ✅ Create ride request
    ride_request = RideRequest(
        ride_id=ride.id,
        user_id=current_user.id,
        status='Pending',  # 🔸 Make sure to include this!
        message=f"I would like to join your ride from {ride.from_location} to {ride.to_location}.",
        request_time=datetime.now(UTC).date() # 🔸 Optional: if your model has this field
    )
    db.session.add(ride_request)

    # ✅ Create a notification
    message = f"{current_user.name} has requested to join your ride from {ride.from_location} to {ride.to_location} on {ride.travel_date.strftime('%d %b %Y')}."
    notification = Notification(
        recipient_id=ride.creator_id,
        sender_id=current_user.id,
        ride_id=ride.id,
        message=message
    )
    db.session.add(notification)

    db.session.commit()

    flash("Ride request sent!", "success")
    return redirect(url_for('ride_posts'))



@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        unread_notifications = Notification.query.filter_by(recipient_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
        return dict(unread_notifications=unread_notifications)
    return dict(unread_notifications=[])

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(recipient_id=current_user.id, is_read=False).update({Notification.is_read: True})
    db.session.commit()
    return '', 204

@app.route('/notification/<int:notif_id>/read_and_redirect')
@login_required
def read_and_redirect(notif_id):
    notification = Notification.query.get_or_404(notif_id)

    if notification.recipient_id != current_user.id:
        abort(403)

    notification.is_read = True
    db.session.commit()

    ride = RidePost.query.get(notification.ride_id)

    # If the current user is the creator of the ride, go to request view
    if ride and current_user.id == ride.creator_id:
        return redirect(url_for('view_ride_request', ride_id=ride.id, requester_id=notification.sender_id))

    # Otherwise, show public ride details
    return redirect(url_for('ride_detail', ride_id=ride.id))

@app.route('/ride/<int:ride_id>')
@login_required
def ride_detail(ride_id):
    ride = RidePost.query.get_or_404(ride_id)

    # Get all ride requests for this ride (assuming model is RideRequest)
    ride_requests = RideRequest.query.filter_by(ride_id=ride.id).all()

    return render_template('ride_detail.html', ride=ride, ride_requests=ride_requests)


@app.route('/ride_request/<int:ride_id>/<int:requester_id>')
@login_required
def view_ride_request(ride_id, requester_id):
    ride = RidePost.query.get_or_404(ride_id)
    requester = User.query.get_or_404(requester_id)

    # Only ride creator can view this page
    if ride.creator_id != current_user.id:
        abort(403)

    return render_template('ride_request.html', ride=ride, requester=requester)

@app.route('/handle_ride_request/<int:ride_id>/<int:requester_id>', methods=['POST'])
@login_required
def handle_ride_request(ride_id, requester_id):
    ride = RidePost.query.get_or_404(ride_id)

    if ride.creator_id != current_user.id:
        abort(403)

    action = request.form.get('action')
    requester = User.query.get_or_404(requester_id)
    ride_request = RideRequest.query.filter_by(ride_id=ride.id, user_id=requester.id).first()

    if not ride_request:
        flash("Ride request not found.", "danger")
        return redirect(url_for('ride_posts'))

    # Handle accept
    if action == 'accept':
        if ride.seats_available <= 0:
            ride_request.status = 'rejected'
            db.session.commit()

            # ❗ Notify requester that ride is already full
            message = f"Sorry, the ride from {ride.from_location} to {ride.to_location} on {ride.travel_date.strftime('%d %b %Y')} is already full."
            notification = Notification(
                recipient_id=requester.id,
                sender_id=current_user.id,
                ride_id=ride.id,
                message=message
            )
            db.session.add(notification)
            db.session.commit()

            flash("No seats available. Request was auto-rejected.", "warning")
        elif ride_request.status == 'accepted':
            flash("This request is already accepted.", "info")
        else:
            ride_request.status = 'accepted'
            ride.seats_available -= 1

            # ✅ Notify requester of acceptance
            message = f"Your request to join the ride from {ride.from_location} to {ride.to_location} on {ride.travel_date.strftime('%d %b %Y')} has been accepted."
            notification = Notification(
                recipient_id=requester.id,
                sender_id=current_user.id,
                ride_id=ride.id,
                message=message
            )
            db.session.add(notification)
            db.session.commit()

            flash(f"You accepted the ride request from {requester.name}.", "success")

    # Handle reject
    elif action == 'reject':
        ride_request.status = 'rejected'

        # ✅ Notify requester of rejection
        message = f"Your request to join the ride from {ride.from_location} to {ride.to_location} on {ride.travel_date.strftime('%d %b %Y')} has been rejected."
        notification = Notification(
            recipient_id=requester.id,
            sender_id=current_user.id,
            ride_id=ride.id,
            message=message
        )
        db.session.add(notification)
        db.session.commit()

        flash(f"You rejected the ride request from {requester.name}.", "warning")
    else:
        flash("Invalid action.", "danger")

    return redirect(url_for('ride_posts'))


@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):  # <- function name changed to avoid clash
    user = User.query.get_or_404(user_id)
    user_rides = RidePost.query.filter_by(creator_id=user_id).order_by(RidePost.created_at.desc()).all()
    
    return render_template('view_profile.html', user=user, rides=user_rides)



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
