from flask_wtf import FlaskForm
# Use StringField instead of EmailField in the import
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, SelectField
# Keep the Email validator import
from wtforms.validators import DataRequired, Length, EqualTo, Optional, InputRequired, Email

# --- RegisterForm ---
class RegisterForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=25)])
    # --- Use StringField for Email ---
    email = StringField('Email', # Changed from EmailField
                       validators=[DataRequired(), Email(message="Please enter a valid email address.")])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         Length(min=6, max=25)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Register')

# --- LoginForm --- (No change needed)
class LoginForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- ChangeUsernameForm --- (No change needed)
class ChangeUsernameForm(FlaskForm):
    new_username = StringField('New Username',
                               validators=[DataRequired(),
                                           Length(min=3, max=25)])
    submit = SubmitField('Change Username')

# --- ChangePasswordForm --- (No change needed)
class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Current Password',
                                 validators=[Optional(),
                                             Length(min=3, max=15)])
    new_password = PasswordField('New Password', validators=[DataRequired(),
                                                             Length(min=3,
                                                                    max=15)])
    confirm_new_password = PasswordField('Confirm New Password',
                                         validators=[DataRequired(),
                                                     EqualTo('new_password', message='New passwords must match.')])
    submit = SubmitField('Change Password')

# --- Add_RecipeForm --- (No change needed)
class Add_RecipeForm(FlaskForm):
    recipe_name = StringField('Recipe Name',
                              validators=[DataRequired()])
    recipe_description = TextAreaField('Recipe Description',
                                       validators=[DataRequired()])
    cooking_time = IntegerField('Cooking Time (minutes)',
                                validators=[DataRequired()])
    servings = IntegerField('Number of Servings', validators=[DataRequired()])
    image = StringField('Recipe Image', validators=[Optional()])
    ingredients = TextAreaField('Ingredients',
                                validators=[DataRequired()])
    recipe_directions = TextAreaField('Directions',
                                      validators=[DataRequired()])
    submit = SubmitField('Add Recipe')

# --- AdminAddUserForm ---
class AdminAddUserForm(FlaskForm):
    
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=25)])
    # --- Use StringField for Email ---
    email = StringField('Email', # Changed from EmailField
                       validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(), Length(min=6, max=25)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message="Passwords must match.")])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')],
                       validators=[InputRequired(message="Please select a role.")], default='user')
    submit = SubmitField('Add User')

# --- AdminEditUserForm ---
class AdminEditUserForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=25)])
    # --- Use StringField for Email ---
    email = StringField('Email', # Changed from EmailField
                       validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')],
                       validators=[InputRequired(message="Please select a role.")])
    submit = SubmitField('Update User')