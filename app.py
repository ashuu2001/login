# # Store this code in 'app.py' file
# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from flask_mysqldb import MySQL
# import MySQLdb.cursors
# import re
# import os
# from werkzeug.utils import secure_filename
# from werkzeug.security import generate_password_hash
# from forms import ResetPasswordForm, PasswordResetRequestForm
# from uuid import uuid4
# from itsdangerous import URLSafeTimedSerializer
# from flask import app
# from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
# import os
# os.urandom(24).hex()  # This generates a 24-byte hexadecimal key
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate

# # import secrets

# # token = secrets.token_urlsafe(16)  # Generate a secure random token


# app = Flask(__name__)


# app.secret_key = '1a2b3c4d5e6d7g8h9i10'
# app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:VkapsIT@localhost:3000/geekprofile'
# # Initialize the db object
# db = SQLAlchemy(app)
# migrate = Migrate(app, db)

# def generate_reset_token(email):
#     serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
#     return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
# example_email = 'ashwitapatidar1@gmail.com'
# token = generate_reset_token(example_email)

# # print("Generated token:", token)

# def verify_reset_token(token, expiration=3600):  # Token expires in 1 hour
#     serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
#     try:
#         email = serializer.loads(
#             token,
#             salt=app.config['SECURITY_PASSWORD_SALT'],
#             max_age=expiration
#         )
#     except (BadSignature, SignatureExpired):
#         return None  # Invalid or expired token
#     return email


# UPLOAD_FOLDER = 'static/uploads'  # Folder to save uploaded files
# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}

# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the folder if it doesn't exist

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PORT']= 3000
# app.config['MYSQL_PASSWORD'] = 'VkapsIT'
# app.config['MYSQL_DB'] = 'geekprofile'


# mysql = MySQL(app)


# @app.route('/')
# @app.route('/login', methods=['GET', 'POST'])
# def login():
# 	msg = ''
# 	if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
# 		username = request.form['username']
# 		password = request.form['password']
# 		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 		cursor.execute(
# 			'SELECT * FROM accounts WHERE username = % s \
# 			AND password = % s', (username, password, ))
# 		account = cursor.fetchone()
# 		if account:
# 			session['loggedin'] = True
# 			session['id'] = account['id']
# 			session['username'] = account['username']
# 			msg = 'Logged in successfully !'
# 			return render_template('index.html', msg=msg)
# 		else:
# 			msg = 'Incorrect username / password !'
# 	return render_template('login.html', msg=msg)


# @app.route('/logout')
# def logout():
#    session.pop('loggedin', None)
#    session.pop('id', None)
#    session.pop('username', None)

#    return redirect(url_for('login'))


# @app.route('/register', methods=['GET', 'POST'])
# def register():
# 	msg = ''
# 	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'address' in request.form and 'city' in request.form and	'country' in request.form and 'postalcode' in request.form and 'organisation' in request.form:
# 		username = request.form['username']
# 		password = request.form['password']
# 		email = request.form['email']
# 		organisation = request.form['organisation']
# 		address = request.form['address']
# 		city = request.form['city']
# 		state = request.form['state']
# 		country = request.form['country']
# 		postalcode = request.form['postalcode']
# 		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 		cursor.execute(
# 			'SELECT * FROM accounts WHERE username = % s', (username, ))
# 		account = cursor.fetchone()
# 		if account:
# 			msg = 'Account already exists !'
# 		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
# 			msg = 'Invalid email address !'
# 		elif not re.match(r'[A-Za-z0-9]+', username):
# 			msg = 'name must contain only characters and numbers !'
# 		else:
# 			cursor.execute('INSERT INTO accounts VALUES \
# 			(NULL, % s, % s, % s, % s, % s, % s, % s, % s, % s)',
# 						(username, password, email, 
# 							organisation, address, city,
# 							state, country, postalcode, ))
# 			mysql.connection.commit()
# 			msg = 'You have successfully registered !'
# 	elif request.method == 'POST':
# 		msg = 'Please fill out the form !'
# 	return render_template('register.html', msg=msg)


# @app.route("/index")
# def index():
# 	if 'loggedin' in session:
# 		return render_template("index.html")
# 	return redirect(url_for('login'))


# @app.route("/display")
# def display():
# 	if 'loggedin' in session:
# 		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 		cursor.execute('SELECT * FROM accounts WHERE id = % s',
# 					(session['id'], ))
# 		account = cursor.fetchone()
# 		return render_template("display.html", account=account)
# 	return redirect(url_for('login'))


# @app.route("/update", methods=['GET', 'POST'])
# def update():
# 	msg = ''
# 	if 'loggedin' in session:
# 		if request.method == 'POST' and 'email' in request.form and 'address' in request.form and 'city' in request.form and 'country' in request.form and 'postalcode' in request.form and 'organisation' in request.form:
# 			# username = request.form['username']
# 			# password = request.form['password']
# 			email = request.form['email']
# 			organisation = request.form['organisation']
# 			address = request.form['address']
# 			city = request.form['city']
# 			state = request.form['state']
# 			country = request.form['country']
# 			postalcode = request.form['postalcode']
# 			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 			cursor.execute(
# 				'SELECT * FROM accounts WHERE username = % s',
# 					(address, ))
# 			account = cursor.fetchone()
# 			if account:
# 				msg = 'Account already exists !'
# 			elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
# 				msg = 'Invalid email address !'
# 			elif not re.match(r'[A-Za-z0-9]+', address):
# 				msg = 'name must contain only characters and numbers !'
# 			else:
# 				cursor.execute('UPDATE accounts SET email =% s, organisation =% s, \
# 				address =% s, city =% s, state =% s, \
# 				country =% s, postalcode =% s WHERE id =% s', (
# 				 email, organisation, 
# 				address, city, state, country, postalcode, 
# 				(session['id'], ), ))
# 				mysql.connection.commit()
# 				msg = 'You have successfully updated !'
# 		elif request.method == 'POST':
# 			msg = 'Please fill out the form !'
# 		return render_template("update.html", msg=msg)
# 	return redirect(url_for('login'))

# @app.route('/upload', methods=['GET', 'POST'])
# def upload_file():
#     if request.method == 'POST':
#         # Check if the POST request has the file part
#         if 'file' not in request.files:
#             flash('No file part')
#             return redirect(request.url)
#         file = request.files['file']
        
#         # If no file is selected
#         if file.filename == '':
#             flash('No selected file')
#             return redirect(request.url)
        
#         # If file is allowed, save it
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)  # Secure the filename
#             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#             flash(f'File {filename} uploaded successfully!')
#             return redirect(url_for('upload_file'))
#         else:
#             flash('File type not allowed.')
#             return redirect(request.url)
#     return render_template('upload.html')


# # @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# # def reset_password(token):
# #     form = ResetPasswordForm()
# #     cursor = db.cursor(dictionary=True)

# #     # Verify the token (pseudo-code, replace with your verification logic)
# #     cursor.execute("SELECT * FROM accounts WHERE reset_token = %s", (token,))
# #     user = cursor.fetchone()
    
# #     if not user:
# #         flash("Invalid or expired token", "danger")
# #         return redirect(url_for('login'))

# #     if form.validate_on_submit():
# #         new_password = form.new_password.data
# #         hashed_password = generate_password_hash(new_password)

# #         # Update password in the database
# #         cursor.execute("UPDATE accounts SET password = %s, reset_token = NULL WHERE id = %s", (hashed_password, user['id']))
# #         db.commit()
        
# #         flash("Your password has been updated successfully!", "success")
# #         return redirect(url_for('login'))

# #     return render_template('reset_password.html', token=token)


# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     from models import User
#     form = ResetPasswordForm()

#     # Querying the database with SQLAlchemy ORM
#     user = db.session.query(User).filter_by(reset_token=token).first()

#     if user:
#         # Your logic for resetting the password
#         if form.validate_on_submit():
#             # Assuming you have a field for new password in your form
#             user.password = form.password.data
#             user.reset_token = None  # Clear reset token after password is updated
#             db.session.commit()  # Save changes to the database
#             flash('Password successfully reset. Please login.', 'success')
#             return redirect(url_for('login'))  # Redirect to login page after reset
#     else:
#         # Handle case where token is invalid or expired
#         flash('Invalid or expired token', 'danger')
    
#     return render_template('reset_password.html', form=form)


# @app.route('/request_reset', methods=['GET', 'POST'])
# def request_reset():
#     form = PasswordResetRequestForm()
#     if form.validate_on_submit():
#         email = form.email.data
#         # Process the email, e.g., check if it exists and send a reset link
#         flash('Password reset link has been sent to your email.', 'success')
#         return redirect(url_for('reset_password', token=token))  # Redirect to login or another page
#     return render_template('request_reset.html', form=form)



# if __name__ == "__main__":
# 	app.run(host="localhost", port=int("5000"), debug=True)

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from forms import ResetPasswordForm, PasswordResetRequestForm
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import re
import os
import MySQLdb.cursors
import secrets
from extensions import db
from models import User  # Import models after db is initialized
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash


token = secrets.token_urlsafe(16)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:VkapsIT@localhost:3000/geekprofile'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# with app.app_context():
#     user = User.query.first()
#     print(user)



# Configurations
app.secret_key = '1a2b3c4d5e6d7g8h9i10'
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PORT'] = 3000
app.config['MYSQL_PASSWORD'] = 'VkapsIT'
app.config['MYSQL_DB'] = 'geekprofile'
app.config['UPLOAD_FOLDER'] = 'static/uploads'



# Initialize extensions

mysql = MySQL(app)

# Token functions
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except (BadSignature, SignatureExpired):
        return None
    return email

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Utility function
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        
        # Check if account exists and password is correct
        if account and check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            msg = 'Logged in successfully!'
            return render_template('index.html', msg=msg)
        else:
            msg = 'Incorrect username / password!'
    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)

   return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    
    if request.method == 'POST':
        print("POST request received.")
        # Print form data to verify what is being submitted
        print(f"Form data: {request.form}")

        # Check if all required fields are present
        missing_fields = []
        required_fields = ['username', 'password', 'email', 'address', 'city','state', 'country', 'postalcode', 
                           'organisation', 'education_level_id', 'gender']
        for field in required_fields:
            if field not in request.form:
                missing_fields.append(field)
        
        if missing_fields:
            print(f"Missing fields: {missing_fields}")
            msg = f"Missing fields: {', '.join(missing_fields)}"
        else:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            organisation = request.form['organisation']
            address = request.form['address']
            city = request.form['city']
            state = request.form['state']
            country = request.form['country']
            postalcode = request.form['postalcode']
            # level = request.form['level']
            education_level_id = request.form['education_level_id']
            gender = request.form['gender']
            
            print(f"Received data: {username}, {password}, {email}, {organisation}, {address}, {city}, {state}, {country}, {postalcode}, {education_level_id}, {gender}")

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists!'
                print("Account already exists.")
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
                print("Invalid email address.")
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only characters and numbers!'
                print("Invalid username.")
            else:
                # Insert the new account into the database
                cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                               (username, password, email, organisation, address, city, state, country, postalcode, education_level_id, gender))
                cursor.execute('INSERT INTO user VALUES (NULL, %s, %s, NULL, %s, %s, %s)', 
                               (email, password, password, password, username))
                mysql.connection.commit()
                msg = 'You have successfully registered!'
                print("Registration successful.")

    else:
        msg = 'Please fill out the form!'
    
    education_levels = [(1, 'High School'), (2, 'Bachelor'), (3, 'Master'), (4, 'PhD')]  # Example data
    return render_template('register.html', msg=msg, education_levels=education_levels)



@app.route("/index")
def index():
	if 'loggedin' in session:
		return render_template("index.html")
	return redirect(url_for('login'))


@app.route("/display")
def display():
	if 'loggedin' in session:
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE id = % s',
					(session['id'], ))
		account = cursor.fetchone()
		return render_template("display.html", account=account)
	return redirect(url_for('login'))


@app.route("/update", methods=['GET', 'POST'])
def update():
    msg = ''
    if 'loggedin' in session:
        if request.method == 'POST' and 'email' in request.form and 'address' in request.form and 'city' in request.form and 'country' in request.form and 'postalcode' in request.form and 'organisation' in request.form and 'education_level_id' in request.form and 'gender' in request.form:
            # username = request.form['username']
            # password = request.form['password']
            email = request.form['email']
            organisation = request.form['organisation']
            address = request.form['address']
            city = request.form['city']
            state = request.form['state']
            country = request.form['country']
            postalcode = request.form['postalcode']
            education_level_id = request.form['education_level_id']
            gender = request.form['gender']

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'SELECT * FROM accounts WHERE email = %s', (email,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists !'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address !'
            elif not re.match(r'[A-Za-z0-9]+', address):
                msg = 'Address must contain only characters and numbers !'
            else:
                cursor.execute('UPDATE accounts SET email = %s, organisation = %s, address = %s, city = %s, state = %s, country = %s, postalcode = %s, education_level_id = %s, gender = %s WHERE id = %s',
                               (email, organisation, address, city, state, country, postalcode, education_level_id, gender, session['id']))
                mysql.connection.commit()
                msg = 'You have successfully updated !'
        elif request.method == 'POST':
            msg = 'Please fill out the form !'
        education_levels = [(1, 'High School'), (2, 'Bachelor'), (3, 'Master'), (4, 'PhD')] 
        return render_template("update.html", msg=msg, education_levels=education_levels)
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the POST request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        
        # If no file is selected
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        # If file is allowed, save it
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Secure the filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash(f'File {filename} uploaded successfully!')
            return redirect(url_for('upload_file'))
        else:
            flash('File type not allowed.')
            return redirect(request.url)
    return render_template('upload.html')


# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     form = ResetPasswordForm()
#     cursor = db.cursor(dictionary=True)

#     # Verify the token (pseudo-code, replace with your verification logic)
#     cursor.execute("SELECT * FROM user WHERE reset_token = %s", (token,))
#     user = cursor.fetchone()
    
#     if not user:
#         flash("Invalid or expired token", "danger")
#         return redirect(url_for('login'))

#     if form.validate_on_submit():
#         new_password = form.new_password.data
#         hashed_password = generate_password_hash(new_password)

#         # Update password in the database
#         cursor.execute("UPDATE user SET password = %s, reset_token = NULL WHERE id = %s", (hashed_password, user['id']))
#         db.commit()
        
#         flash("Your password has been updated successfully!", "success")
#         return redirect(url_for('login'))

#     return render_template('reset_password.html', token=token)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPasswordForm()
    
    # Verify the reset token and retrieve the user's email
    email = verify_reset_token(token)

    if not email:
        flash('The reset token is invalid or has expired.', 'error')
        return redirect(url_for('request_reset'))

    if form.validate_on_submit():
        new_password = form.new_password.data
        
        # Hash the new password
        hashed_password = generate_password_hash(new_password)
        
        # Update the password in both 'user' and 'accounts' tables
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Update password in 'user' table
        cursor.execute('UPDATE user SET password = %s, new_password = %s, confirm_password = %s WHERE email = %s', 
                       (hashed_password, hashed_password, hashed_password, email))
        
        # Update password in 'accounts' table (if it also requires the password field)
        cursor.execute('UPDATE accounts SET password = %s WHERE email = %s', (hashed_password, email))
        
        mysql.connection.commit()

        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form)



@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        print('Form validated and submitted!')
        email = form.email.data
        
        # Execute MySQL query to check if email exists in 'accounts' table (or 'user' table, based on your DB schema)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
        user = cursor.fetchone()
        print(f"User fetched from database: {user}")  # Debugging line


        if user:
            # Generate a token for password reset (you might need to implement token generation here)
            token = generate_reset_token(email)  # Assuming you have a function to generate the token

            # Redirect to the reset password page, passing the token as a URL parameter
            print(f"Redirecting with token: {token}")
            return redirect(url_for('reset_password', token=token))
        else:
            # If no user found with that email, show an error message
            flash('No account found with that email address', 'error')
    else:
     print('Form not validated!', form.errors)
    return render_template('request_reset.html', form=form)


if __name__ == "__main__":
	app.run(host="localhost", port=int("7000"), debug=True)