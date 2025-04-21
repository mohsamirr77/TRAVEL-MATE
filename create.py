from app import app, db
from models import Admin
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()
    admin = Admin(email='admin@example.com', password=generate_password_hash('admin123'))
    db.session.add(admin)
    db.session.commit()
    print("Admin created successfully.")
