from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, EqualTo
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Email, ValidationError

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message="Passwords must match")])
    submit = SubmitField('Reset Password')

# def email_exists(form, email):
#     from models import User
#     email = email
#     user = User.query.filter_by(email=email).first()
#     if not user:
#         raise ValidationError('This email is not registered in our system.')
# def email_exists(form, email):
#     from models import accounts
#     print(f"Checking if email exists: {email}")  # Debugging line
#     user = accounts.query.filter_by(email=email).first()
#     if not user:
#         raise ValidationError('This email is not registered in our system.')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email Id', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password')

    # def validate_email(self, email):
    #     from models import User
    #     user = User.query.filter_by(email=email.data).first()
    #     if not user:
    #         raise ValidationError('No account found with that email.')