# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False).
# from app import db  # Make sure this is imported if db is initialized in a different file.

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     reset_token = db.Column(db.String(120), unique=True, nullable=True)
#     password = db.Column(db.String(120), nullable=False)

#     def __repr__(self):
#         return f'<User {self.username}>'

from itsdangerous import URLSafeTimedSerializer, Serializer
from extensions import db  # Ensure this is the correct import


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    reset_token = db.Column(db.String(200), nullable=True)
    new_password = db.Column(db.String(60), nullable=False)
    confirm_password = db.Column(db.String(60), nullable=False)
    

    # def get_reset_token(self, expire_time=120):
    #     from app import app
    #     serial_key = Serializer(app.config['SECRET_KEY'], expire_time)
    #     return serial_key.dumps({'user_id': self.id}).decode('utf-8')
    def generate_reset_token(email):
     from app import app
     s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
     return s.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def verify_reset_token(token):
        from app import app
        serial_key = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = serial_key.loads(token)['user_id']
        except:
            return None
        return user_id.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}','{self.email}')"
