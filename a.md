Okay, I can help you with these modifications and features for your `MyCookBook_v2` Flask application.

Here's the plan:

1.  **Modify `forms.py` and `routes.py`** to allow users logged in via Google (with `password_set: false`) to set a password without providing the current one.
2.  **Introduce an `email` field** to the user schema, update the **`routes.py`** (`google_callback`, `register`, `change_username`) to use this field for Google login linking and handle potential conflicts.
3.  **Create new forms in `forms.py`**, new **routes in `routes.py`**, and new **templates** for Admin User CRUD (Add, Edit) functionality.
4.  **Provide a new `initialize_database.py` script** to set up the MongoDB database from scratch, including collections, initial dropdown data, the new `email` field, and an optional default admin user.

Let's implement these changes step by step.

**1. Fix Password Change Requirement**

We need to adjust the `change_password` route to check if the user needs to set a password initially. We'll also modify the form slightly to reflect this.

**`MyCookBook_v2/mycookbook/forms.py` (Modified `ChangePasswordForm`)**

```python
# Add Optional to the imports if not already there
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField # Keep other imports
from flask_wtf import FlaskForm # Keep other imports

# Keep RegisterForm, LoginForm, ChangeUsernameForm, Add_RecipeForm as they are

class ChangePasswordForm(FlaskForm):
    # Make old_password optional in the form definition
    old_password = PasswordField('Current Password',
                                 validators=[Optional(), # Changed from DataRequired()
                                             Length(min=3, max=15)])
    new_password = PasswordField('New Password', validators=[DataRequired(),
                                                             Length(min=3,
                                                                    max=15)])
    confirm_new_password = PasswordField('Confirm New Password',
                                         validators=[DataRequired(),
                                                     EqualTo('new_password', message='New passwords must match.')]) # Added EqualTo validator and message
    submit = SubmitField('Change Password')

# Add the new Admin forms later (see step 3)

```

**`MyCookBook_v2/mycookbook/routes.py` (Modified `change_password` route)**

```python
# Add necessary imports if not already present
from flask import render_template, url_for, flash, redirect, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from mycookbook import app, mongo, oauth # Keep other imports
from mycookbook.forms import ChangePasswordForm # Keep other forms imports

# Keep other routes and helper functions

# Change password
@app.route("/change_password/<username>", methods=['GET', 'POST'])
def change_password(username):
    '''
    UPDATE.
    Allows user to change the current password or set it for the first time
    if logged in via Google initially.
    It calls the ChangePasswordForm class from forms.py.
    Checks if the current password is correct (if password was already set),
    validates new password. Then if new password matches confirm password field,
    insert it to the database and set password_set to True.
    '''
    # Prevents guest users from viewing the form
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in and can only change your own password!', 'warning')
        return redirect(url_for('login'))

    users = mongo.db.users
    user = users.find_one({'username': session['username']})

    if not user:
        flash('User not found.', 'error')
        session.pop("username", None)
        return redirect(url_for('login'))

    # Check if the user needs to set the password for the first time
    password_needs_set = not user.get('password_set', True)

    form = ChangePasswordForm()

    # Customize form based on whether the password needs to be set
    if password_needs_set:
        # If setting password for the first time, remove the old_password field's label/requirement visually
        # (The validator is already Optional, but we adjust the template experience)
        # We can pass a flag to the template or adjust the form field here if needed
        # For simplicity, we rely on the logic below to bypass the check.
        # No change needed to the form object itself here, logic handles the check.
        pass # Placeholder for potential future form adjustments if needed
    else:
        # If password is set, old_password is required logically
        # Ensure the Optional validator doesn't bypass our check below
        pass

    if form.validate_on_submit():
        new_password = form.new_password.data
        old_password = form.old_password.data # Get data even if optional

        # If password was already set, verify the old password
        if not password_needs_set:
            if not old_password:
                 flash('Current password is required.', 'danger')
                 # Pass the flag to the template
                 return render_template('change_password.html', username=username, form=form, title='Change Password', password_needs_set=password_needs_set)
            if not user.get('password') or not check_password_hash(user['password'], old_password):
                flash('Incorrect current password! Please try again', 'danger')
                # Pass the flag to the template
                return render_template('change_password.html', username=username, form=form, title='Change Password', password_needs_set=password_needs_set)

        # If validation passes (including old password check if applicable), update the password
        hashed_new_password = generate_password_hash(new_password)
        users.update_one({'_id': user['_id']},
                         {'$set': {
                             'password': hashed_new_password,
                             'password_set': True # Ensure this is set to True
                         }})
        flash("Success! Your password was updated.", 'success')
        return redirect(url_for('account_settings', username=session['username']))

    # Pass the flag to the template for conditional rendering
    return render_template('change_password.html', username=username, form=form, title='Change Password', password_needs_set=password_needs_set)

# Keep other routes
```

**`MyCookBook_v2/mycookbook/templates/change_password.html` (Modified)**

We need to conditionally hide or disable the "Current Password" field based on the `password_needs_set` flag passed from the route.

```html
{% extends 'base.html' %} {% block content %}
<div class="log-reg-container">
  <section class="login-reg-section center-align">
    <a href="{{ url_for('home') }}">
      <img
        src="{{ url_for('static', filename='img/logo.png') }}"
        class="logo-login-register hide-on-med-and-down"
        alt="My CookBook Logo"
      />
    </a>
    {% if password_needs_set %}
    <h1 class="secondary-heading heading-black uppercase">Set Your Password</h1>
    <p>Set a password for your account for future logins.</p>
    {% else %}
    <h1 class="secondary-heading heading-black uppercase">Change Password</h1>
    {% endif %}

    <div class="row">
      <form method="POST" action="">
        {{ form.hidden_tag() }} {% if not password_needs_set %}
        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">lock_outline</i> {{
            form.old_password.label(class="active") }} {{
            form.old_password(placeholder="Enter current password",
            required=True) }} {# Add required attribute visually #} {% if
            form.old_password.errors %} {% for error in form.old_password.errors
            %} <small class="text-red helper-text">{{ error }}</small> {# Use
            helper-text class #} {% endfor %} {% endif %} {% with messages =
            get_flashed_messages(category_filter=["danger"]) %} {% if messages
            %} {% for message in messages %} {% if 'Incorrect current password'
            in message %}
            <small class="text-red helper-text">{{ message }}</small>
            {% endif %} {% if 'Current password is required' in message %}
            <small class="text-red helper-text">{{ message }}</small>
            {% endif %} {% endfor %} {% endif %} {% endwith %}
          </div>
        </div>
        {% endif %}

        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">lock</i> {{
            form.new_password(placeholder="Enter new password",
            id="new_password", required=True) }}
            <label for="new_password"
              >New Password
              <i
                class="fas fa-question-circle tooltipped"
                data-position="top"
                data-tooltip="3-15 characters, case sensitive"
              ></i
            ></label>
            {% if form.new_password.errors %} {% for error in
            form.new_password.errors %}
            <small class="text-red helper-text">{{ error }}</small>
            {% endfor %} {% endif %}
          </div>
        </div>
        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">check</i> {# {{
            form.confirm_new_password.label }} #} {# Label might be redundant
            with placeholder #} {{
            form.confirm_new_password(placeholder="Confirm new password",
            required=True) }} {% if form.confirm_new_password.errors %} {% for
            error in form.confirm_new_password.errors %}
            <small class="text-red helper-text">{{ error }}</small>
            {% endfor %} {% endif %} {% with messages =
            get_flashed_messages(category_filter=["danger"]) %} {% if messages
            %} {% for message in messages %} {% if 'New passwords do not match'
            in message %}
            <small class="text-red helper-text">{{ message }}</small>
            {% endif %} {% endfor %} {% endif %} {% endwith %}
          </div>
        </div>
        <div class="row center-align">
          {% with messages = get_flashed_messages(category_filter=["success",
          "info", "warning"]) %} {% if messages %} {% for message in messages %}
          <small class="text-green">{{ message }}</small> {# Use appropriate
          color #} {% endfor %} {% endif %} {% endwith %}
        </div>
        <div class="row">
          {# Wrap buttons in a row for better alignment #}
          <div class="col s6 right-align margin-bottom-large">
            <a
              href="{{ url_for('account_settings', username = session.username) }}"
              class="btn z-depth-2 btn-change btn-form btn-secondary waves-effect waves-light uppercase"
              name="action"
            >
              Cancel
            </a>
          </div>
          <div class="col s6 left-align margin-bottom-large">
            {{ form.submit(class="btn z-depth-3 btn-change btn-form btn-coral-2
            uppercase")}}
          </div>
        </div>
      </form>
    </div>
  </section>
</div>
{% endblock %}
```

**Explanation:**

- **forms.py:** `old_password` validator changed from `DataRequired()` to `Optional()`. Added `EqualTo('new_password')` validator to `confirm_new_password`.
- **routes.py:**
  - Fetches the user document to check the `password_set` flag.
  - If `password_needs_set` is `False` (meaning password was already set), it checks if `old_password` was provided and if it's correct using `check_password_hash`.
  - If `password_needs_set` is `True`, it bypasses the `old_password` check.
  - Upon successful update, it explicitly sets `password_set: True` in the database.
  - Passes the `password_needs_set` boolean flag to the template.
- **change_password.html:**
  - Uses `{% if not password_needs_set %}` to conditionally render the "Current Password" input field block.
  - Adjusted labels, icons, and error message display for clarity.

**2. Fix Google Login Account Linking**

This requires adding an `email` field to the user schema and updating the Google callback logic, registration, and potentially username change.

**`MyCookBook_v2/mycookbook/routes.py` (Modified `google_callback`, `register`, `change_username`)**

```python
# Add necessary imports
import os # If not already imported
import traceback # If not already imported
from flask import render_template, url_for, flash, redirect, request, session, g
from authlib.integrations.flask_client import OAuth
from mycookbook import app, mongo, oauth
from werkzeug.security import generate_password_hash, check_password_hash
# Make sure RegisterForm and ChangeUsernameForm are imported
from mycookbook.forms import RegisterForm, LoginForm, ChangeUsernameForm, ChangePasswordForm, Add_RecipeForm
from flask_pymongo import pymongo
from bson.objectid import ObjectId
import math
from functools import wraps

# Keep MongoDB Collections variables
users_coll = mongo.db["users"]
recipes_coll = mongo.db["recipes"]
cuisines_coll = mongo.db["cuisines"]
diets_coll = mongo.db["diets"]
meals_coll = mongo.db["meals"]

# Keep context_processor and admin_required decorator

'''
GOOGLE AUTHENTICATION
'''
@app.route('/google/login')
def google_login():
    """Chuyển hướng người dùng đến trang đăng nhập Google."""
    redirect_uri = url_for('google_callback', _external=True)
    # Ensure the redirect URI matches one configured in Google Cloud Console
    # For local development, it's often http://127.0.0.1:5000/google/callback or http://localhost:5000/google/callback
    print(f"DEBUG: Redirect URI for Google Auth: {redirect_uri}")
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    """Xử lý callback từ Google sau khi người dùng xác thực."""
    try:
        token = oauth.google.authorize_access_token()
        if not token:
            flash("Google authentication failed: Could not authorize access token.", "danger")
            return redirect(url_for('login'))

        # Use the token to fetch user info
        # Authlib automatically uses the userinfo_endpoint configured in __init__.py
        resp = oauth.google.get('userinfo') # Simplified call using configured endpoint
        resp.raise_for_status()
        user_info = resp.json()

        google_email = user_info.get('email')
        google_name = user_info.get('name') # Get name as potential default username fallback

        if not google_email:
            flash("Could not retrieve email address from Google.", "danger")
            return redirect(url_for('login'))

        # --- CORE CHANGE: Look up user by EMAIL ---
        existing_user = users_coll.find_one({'email': google_email})

        if existing_user:
            # User found by email - Log them in
            session['username'] = existing_user['username'] # Log in with their current username
            g._current_user = existing_user # Update g object
            flash(f"Welcome back, {existing_user['username']}!", "success")
            # Optional: Update last login time or other fields if needed
            # users_coll.update_one({'_id': existing_user['_id']}, {'$set': {'last_login': datetime.utcnow()}})

            password_needs_set = not existing_user.get('password_set', True)
            if password_needs_set:
                flash("Please set a password for your account.", "info")
                # Redirect to settings or change password page
                return redirect(url_for('change_password', username=session['username'])) # Redirect to set password
            return redirect(url_for('home'))
        else:
            # --- User NOT found by email - Create NEW user ---

            # Decide on the initial username.
            # Option 1: Use email (ensure it doesn't conflict with existing usernames)
            # Option 2: Use name from Google (ensure uniqueness)
            # Option 3: Use email prefix (ensure uniqueness)
            # Let's try using the email as username initially, but check for conflicts.
            initial_username = google_email
            username_conflict = users_coll.find_one({'username': initial_username})

            if username_conflict:
                # Handle username conflict (e.g., append random digits, use Google name)
                # For simplicity, let's try the name from Google if available
                if google_name:
                    potential_username = google_name.replace(" ", "").lower() # Basic cleanup
                    if not users_coll.find_one({'username': potential_username}):
                        initial_username = potential_username
                    else:
                        # If name also conflicts, append part of email or random chars (more robust needed for production)
                        initial_username = google_email.split('@')[0] + "_" + os.urandom(3).hex()
                else:
                     # If no name, use email prefix + random
                     initial_username = google_email.split('@')[0] + "_" + os.urandom(3).hex()

                # Final check - although unlikely to conflict now
                if users_coll.find_one({'username': initial_username}):
                     flash("Failed to create a unique username. Please try registering manually.", "danger")
                     return redirect(url_for('register'))


            # Create the new user document
            new_user_data = {
                "username": initial_username,
                "email": google_email, # Store the email
                "password": None,      # No password initially
                "user_recipes": [],
                "role": "user",
                "password_set": False # Password needs to be set
                # Add any other default fields like creation date etc.
                # "created_at": datetime.utcnow()
            }
            result = users_coll.insert_one(new_user_data)
            new_user = users_coll.find_one({"_id": result.inserted_id})

            session['username'] = new_user['username'] # Log in with the new username
            g._current_user = new_user # Update g object
            flash(f"Google sign-in successful! Welcome, {new_user['username']}. Please set a password for your account.", "success")
            # Redirect to set password page
            return redirect(url_for('change_password', username=session['username']))

    except Exception as e:
        # Log the error for debugging
        app.logger.error(f"Google Callback Error: {e.__class__.__name__}: {e}")
        traceback.print_exc()
        flash("An error occurred during Google authentication. Please try logging in again.", "danger")
        return redirect(url_for('login'))


# --- Update Register Route ---
@app.route("/register", methods=['GET', 'POST'])
def register():
    '''
    CREATE.
    Creates a new account; it calls the RegisterForm class from forms.py.
    Checks if the username or email is not already existing in the database,
    hashes the entered password and adds a new user to session.
    Requires email field now.
    '''
    if 'username' in session:
        flash('You are already registered and logged in!', 'info')
        return redirect(url_for('home'))

    # --- NOTE: RegisterForm needs an email field added ---
    # --- Go back to forms.py and add it ---
    form = RegisterForm() # Assuming RegisterForm now includes an email field

    if form.validate_on_submit():
        users = users_coll
        existing_username = users.find_one({'username': form.username.data})
        # --- Check for existing email ---
        existing_email = users.find_one({'email': form.email.data}) # Assuming form has email.data

        if existing_username:
            flash("Sorry, this username is already taken!", 'danger')
            return redirect(url_for('register'))
        # --- Check email conflict ---
        if existing_email:
            flash("This email address is already associated with an account.", 'danger')
            return redirect(url_for('register'))

        # If username and email are unique, proceed
        hashed_password = generate_password_hash(form.password.data)
        new_user = {
            "username": form.username.data,
            "email": form.email.data, # Store email
            "password": hashed_password,
            "user_recipes": [],
            "role": "user",
            "password_set": True # Password is set during registration
            # "created_at": datetime.utcnow()
        }
        users.insert_one(new_user)
        # add new user to the session
        session["username"] = form.username.data
        g._current_user = new_user # Set g object
        flash('Your account has been successfully created.', 'success')
        return redirect(url_for('home'))

    return render_template('register.html', form=form,  title='Register')


# --- Update Change Username Route ---
@app.route("/change_username/<username>", methods=['GET', 'POST'])
def change_username(username):
    '''
    UPDATE.
    Allows user to change the current username.
    It calls the ChangeUsernameForm class from forms.py.
    Checks if the new username is unique and not exist in database,
    then updates the username, clears the session and redirects user to login page.
    Email remains unchanged.
    '''
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in and can only change your own username!', 'warning')
        return redirect(url_for('login'))

    users = users_coll
    user = users.find_one({'username': session['username']})
    if not user:
        flash('User not found.', 'error')
        session.pop("username", None)
        return redirect(url_for('login'))

    form = ChangeUsernameForm()
    if form.validate_on_submit():
        new_username = form.new_username.data
        # Check if the new username is the same as the old one
        if new_username == username:
             flash('New username cannot be the same as the current username.', 'warning')
             return redirect(url_for('change_username', username=username))

        # Check if the new username is already taken by someone else
        existing_user = users.find_one({'username': new_username})
        if existing_user:
            flash('Sorry, that username is already taken. Try another one.', 'danger')
            return redirect(url_for('change_username', username=username))
        else:
            # Update the username in the database
            users.update_one(
                {"_id": user['_id']},
                {"$set": {"username": new_username}})

            # Clear the session and redirect to login page forcing re-login
            flash("Your username was updated successfully. Please log in with your new username.", 'success')
            session.pop("username", None)
            g.pop('_current_user', None) # Clear g object too
            return redirect(url_for("login"))

    # Pass current username for display
    return render_template('change_username.html',
                           username=username, # Pass the actual current username
                           form=form, title='Change Username')


# Keep other routes (home, all_recipes, single_recipe, my_recipes, add/insert/edit/update/delete recipe, login, logout, account_settings, delete_account, error handlers, search)

# --- Add Admin CRUD Routes (see step 3) ---

```

**`MyCookBook_v2/mycookbook/forms.py` (Add EmailField to `RegisterForm`)**

```python
# Add EmailField and Email validator
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, EmailField, SelectField # Added EmailField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email # Added Email validator

# Keep other imports and forms

class RegisterForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=25)]) # Increased max length slightly
    # --- Add Email Field ---
    email = EmailField('Email',
                       validators=[DataRequired(), Email(message="Please enter a valid email address.")])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         Length(min=6, max=25)]) # Increased min length for security
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Register')


class ChangeUsernameForm(FlaskForm):
    new_username = StringField('New Username',
                               validators=[DataRequired(),
                                           Length(min=3, max=25)]) # Increased max length
    submit = SubmitField('Change Username')


# Keep ChangePasswordForm, Add_RecipeForm

# --- Add Admin Forms (see step 3) ---

```

**`MyCookBook_v2/mycookbook/templates/register.html` (Add Email Field)**

```html
{% extends 'base.html' %} {% block content %}
<div class="log-reg-container">
  <section class="login-reg-section center-align margin-top-large">
    <a href="{{ url_for('home') }}">
      <img
        src="{{ url_for('static', filename='img/logo.png') }}"
        class="logo-login-register hide-on-med-and-down"
        alt="My CookBook Logo"
      />
    </a>
    <h1 class="secondary-heading heading-black uppercase">Create account</h1>
    <div class="row">
      <form method="POST" action="" class="col s12">
        {{ form.hidden_tag() }}
        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">person</i>
            {{ form.username(placeholder="Enter username", id="username",
            required=True) }}
            <label for="username"
              >Username
              <i
                class="fas fa-question-circle tooltipped"
                data-position="top"
                data-tooltip="3-25 characters, case sensitive"
              ></i
            ></label>
            {% if form.username.errors %} {% for error in form.username.errors
            %}
            <small class="text-red helper-text">{{ error }}</small>
            {% endfor %} {% endif %} {# Flash message specific to username
            conflict #} {% with messages =
            get_flashed_messages(category_filter=["danger"]) %} {% if messages
            %} {% for message in messages %} {% if 'username is already taken'
            in message %}
            <small class="text-red helper-text">{{ message }}</small>
            {% endif %} {% endfor %} {% endif %} {% endwith %}
          </div>
        </div>
        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">email</i>
            {{ form.email(placeholder="Enter email address", id="email",
            type="email", required=True) }}
            <label for="email">Email</label>
            {% if form.email.errors %} {% for error in form.email.errors %}
            <small class="text-red helper-text">{{ error }}</small>
            {% endfor %} {% endif %} {# Flash message specific to email conflict
            #} {% with messages =
            get_flashed_messages(category_filter=["danger"]) %} {% if messages
            %} {% for message in messages %} {% if 'email address is already
            associated' in message %}
            <small class="text-red helper-text">{{ message }}</small>
            {% endif %} {% endfor %} {% endif %} {% endwith %}
          </div>
        </div>
        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">lock</i>
            {{ form.password (placeholder="Enter password", id="password",
            type="password", required=True) }}
            <label for="password"
              >Password
              <i
                class="fas fa-question-circle tooltipped"
                data-position="top"
                data-tooltip="6-25 characters, case sensitive"
              ></i
            ></label>
            {% if form.password.errors %} {% for error in form.password.errors
            %}
            <small class="text-red helper-text">{{ error }}</small>
            {% endfor %} {% endif %}
          </div>
        </div>
        <div class="row">
          <div class="input-field col s12">
            <i class="material-icons prefix">check</i> {# Changed icon #} {# {{
            form.confirm_password.label }} #} {# Label might be redundant #} {{
            form.confirm_password(placeholder="Confirm password",
            type="password", required=True) }} {% if
            form.confirm_password.errors %} {% for error in
            form.confirm_password.errors %}
            <small class="text-red helper-text">{{ error }}</small>
            {% endfor %} {% endif %}
          </div>
        </div>
        <div class="row center-align">
          {% with messages = get_flashed_messages(with_categories=true) %} {% if
          messages %} {% for category, message in messages %} {% if category ==
          'success' %}
          <small class="text-green">{{ message }}</small>
          {% elif category == 'danger' and 'username is already taken' not in
          message and 'email address is already associated' not in message %}
          <small class="text-red">{{ message }}</small> {# General errors #} {%
          elif category != 'danger' %}
          <small
            class="{{ 'text-yellow' if category == 'warning' else ('text-blue' if category == 'info' else 'text-grey') }}"
            >{{ message }}</small
          >
          {% endif %} {% endfor %} {% endif %} {% endwith %}
        </div>
        <div class="row">
          <div class="col s12 center-align">
            {{ form.submit(class="btn btn-form btn-main btn-coral z-depth-3
            uppercase") }}
          </div>
        </div>
        <div class="row center-align">
          <div class="col s12">
            <small
              >Already a user?
              <a href="{{ url_for('login') }}">Login here!</a></small
            >
          </div>
        </div>
      </form>
    </div>
  </section>
</div>
{% endblock %}
```

**Explanation:**

- **Schema:** We've conceptually added an `email` field. The new setup script (Step 4) will handle its creation in MongoDB. Existing users would need a separate migration script if the database wasn't being reset, but the request asks for a _new_ setup script.
- **google_callback:** Now searches for users by `email`. If found, logs them in using their existing `username`. If not found, creates a new user, storing the `email`, generating a unique `username` (with basic conflict handling - **Note:** this could be made more robust), and setting `password_set: false`. New users are redirected to set their password.
- **Register Route & Form:** Added an `EmailField` to `RegisterForm` and the corresponding input to `register.html`. The `register` route now checks for both username and email conflicts before creating the user and stores the email. `password_set` is `True` for regular registrations.
- **Change Username Route:** Primarily ensures the new username doesn't conflict. The user's `email` remains unchanged during this process. Forces re-login after successful change.
- **Templates:** Updated `register.html` to include the email field.

**Potential Issues/Edge Cases:**

- **Username/Email Uniqueness:** The current implementation assumes usernames must be unique, and emails linked via Google should also be unique _among Google-linked accounts_. The registration process now also checks for email uniqueness. You might need stricter database-level unique indexes depending on your requirements.
- **Username Generation:** The conflict resolution for usernames generated during Google signup is basic. For a production system, a more robust method (e.g., checking against a loop, using UUIDs, allowing the user to choose) might be needed if email/name conflicts are common.
- **Email Changes:** This implementation assumes the `email` field set via Google or registration is immutable. If you need users to change their primary email later, you'd need additional logic and verification steps.

**3. Add Admin User CRUD Functionality**

Now, let's add the forms, routes, and templates for admin user management.

**`MyCookBook_v2/mycookbook/forms.py` (Add Admin Forms)**

```python
# Keep existing imports and forms
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, EmailField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email, InputRequired # Added InputRequired

# ... (RegisterForm, LoginForm, ChangeUsernameForm, ChangePasswordForm, Add_RecipeForm)

# --- Admin Add User Form ---
class AdminAddUserForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=25)])
    email = EmailField('Email',
                       validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(), Length(min=6, max=25)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message="Passwords must match.")])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')],
                       validators=[InputRequired(message="Please select a role.")]) # Use InputRequired for SelectField
    submit = SubmitField('Add User')


# --- Admin Edit User Form ---
class AdminEditUserForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=25)])
    email = EmailField('Email',
                        validators=[DataRequired(), Email()]) # Allow editing email? Decide based on policy.
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')],
                       validators=[InputRequired(message="Please select a role.")])
    # Optional: Add a way to reset password, could be a separate button/route or a checkbox here
    # reset_password = BooleanField('Reset Password (send email link - requires email setup)')
    submit = SubmitField('Update User')
```

**`MyCookBook_v2/mycookbook/routes.py` (Add Admin CRUD Routes)**

```python
# Keep existing imports and routes
from bson.objectid import ObjectId
from functools import wraps
# Make sure admin forms are imported
from mycookbook.forms import AdminAddUserForm, AdminEditUserForm

# Keep context_processor and admin_required decorator

# --- ADMIN ROUTES ---

@app.route('/admin/users')
@admin_required
def admin_users():
    # Fetch all users except the current admin to prevent self-modification via list
    # Though edit/delete routes have specific checks too
    all_users = list(users_coll.find({'username': {'$ne': session.get('username')}}).sort('username', 1))
    current_admin_user = users_coll.find_one({'username': session.get('username')})
    return render_template('admin_users.html',
                           users=all_users,
                           current_admin_user=current_admin_user, # Pass current admin separately if needed
                           title='Admin - Manage Users')

# --- Admin Add User ---
@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    form = AdminAddUserForm()
    if form.validate_on_submit():
        users = users_coll
        existing_username = users.find_one({'username': form.username.data})
        existing_email = users.find_one({'email': form.email.data})

        if existing_username:
            flash(f"Username '{form.username.data}' is already taken.", 'danger')
        elif existing_email:
             flash(f"Email '{form.email.data}' is already associated with an account.", 'danger')
        else:
            # Hash the password
            hashed_password = generate_password_hash(form.password.data)
            # Create the new user document
            new_user_data = {
                "username": form.username.data,
                "email": form.email.data,
                "password": hashed_password,
                "role": form.role.data,
                "password_set": True, # Password is set by admin
                "user_recipes": []
                # "created_at": datetime.utcnow()
            }
            users.insert_one(new_user_data)
            flash(f"User '{form.username.data}' added successfully.", 'success')
            return redirect(url_for('admin_users'))

    return render_template('admin_add_user.html', form=form, title='Admin - Add User')


# --- Admin Edit User ---
@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        flash("Invalid User ID format.", "danger")
        return redirect(url_for('admin_users'))

    user_to_edit = users_coll.find_one({"_id": oid})

    if not user_to_edit:
        flash("User not found.", "error")
        return redirect(url_for('admin_users'))

    # Prevent admin from editing themselves via this route (extra precaution)
    if user_to_edit['username'] == session.get('username'):
         flash("Admins cannot edit their own profile via this page. Use regular account settings.", "warning")
         return redirect(url_for('admin_users'))

    form = AdminEditUserForm(obj=user_to_edit) # Pre-populate form

    if form.validate_on_submit():
        new_username = form.username.data
        new_email = form.email.data
        new_role = form.role.data

        # Check for username conflict (if changed)
        if new_username != user_to_edit['username']:
            existing_username = users_coll.find_one({'username': new_username, '_id': {'$ne': oid}})
            if existing_username:
                flash(f"Username '{new_username}' is already taken.", 'danger')
                # Re-render form with error
                return render_template('admin_edit_user.html', form=form, user=user_to_edit, title='Admin - Edit User')

        # Check for email conflict (if changed)
        if new_email != user_to_edit.get('email'): # Use .get() for safety if email might be missing
            existing_email = users_coll.find_one({'email': new_email, '_id': {'$ne': oid}})
            if existing_email:
                flash(f"Email '{new_email}' is already associated with another account.", 'danger')
                 # Re-render form with error
                return render_template('admin_edit_user.html', form=form, user=user_to_edit, title='Admin - Edit User')

        # Prevent changing role *to* admin if you want to limit admin creation
        # Or prevent changing role *of* admin if needed (though self-edit is already blocked)
        # if new_role == 'admin' and user_to_edit['role'] != 'admin':
        #    flash("Cannot elevate users to admin via this form.", "warning") # Example restriction
        #    return redirect(url_for('admin_users'))

        # Update user document
        users_coll.update_one({"_id": oid}, {
            "$set": {
                "username": new_username,
                "email": new_email,
                "role": new_role
                # Add other fields if the form included them (e.g., password reset flag)
            }
        })
        flash(f"User '{new_username}' updated successfully.", 'success')
        return redirect(url_for('admin_users'))

    # On GET request or validation failure
    return render_template('admin_edit_user.html', form=form, user=user_to_edit, title='Admin - Edit User')


# --- Admin Delete User (Keep existing, ensure checks are robust) ---
@app.route('/admin/delete_user/<user_id>')
@admin_required
def admin_delete_user(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        flash("Invalid User ID format.", "danger")
        return redirect(url_for('admin_users'))

    user_to_delete = users_coll.find_one({"_id": oid})

    if not user_to_delete:
         flash("User not found!", "error")
         return redirect(url_for('admin_users'))

    # Prevent admin from deleting themselves
    if user_to_delete['username'] == session.get('username'):
         flash("You cannot delete your own admin account.", "warning")
         return redirect(url_for('admin_users'))

    # Optional: Prevent deleting other admins
    # if user_to_delete.get('role') == 'admin':
    #     flash("Cannot delete other admin accounts.", "warning")
    #     return redirect(url_for('admin_users'))

    # Delete associated recipes (decision from original code/request)
    # Consider consequences: Keep recipes but orphan them? Assign to admin?
    all_user_recipes_ids = user_to_delete.get("user_recipes", [])
    if all_user_recipes_ids:
         try:
             # Convert potential string IDs to ObjectIds if necessary
             object_ids = [ObjectId(r_id) for r_id in all_user_recipes_ids]
             delete_result = recipes_coll.delete_many({"_id": {"$in": object_ids}})
             print(f"DEBUG: Deleted {delete_result.deleted_count} recipes for user {user_to_delete['username']}")
         except Exception as e:
              app.logger.error(f"Error deleting recipes for user {user_id}: {e}")
              flash(f"Could not delete recipes associated with user {user_to_delete['username']}. Please check logs.", "warning")
              # Decide whether to proceed with user deletion or stop

    # Delete the user
    users_coll.delete_one({"_id": oid})
    flash(f"User '{user_to_delete['username']}' and their recipes have been deleted.", "success")
    return redirect(url_for('admin_users'))


# Keep other non-admin routes
```

**`MyCookBook_v2/mycookbook/templates/admin_add_user.html` (New File)**

```html
{% extends 'base.html' %} {% block content %}
<div class="container margin-top-large">
  <h1 class="secondary-heading uppercase center-align">Admin - Add New User</h1>

  {% include "partials/toast_messages.html" %} {# Include flash messages partial
  #}

  <div class="row">
    <form
      method="POST"
      action="{{ url_for('admin_add_user') }}"
      class="col s12 m8 offset-m2 l6 offset-l3 card-panel"
    >
      {{ form.hidden_tag() }}

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">person</i>
          {{ form.username.label }} {{ form.username(required=True) }} {% if
          form.username.errors %} {% for error in form.username.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">email</i>
          {{ form.email.label }} {{ form.email(type="email", required=True) }}
          {% if form.email.errors %} {% for error in form.email.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">lock</i>
          {{ form.password.label }} {{ form.password(type="password",
          required=True) }} {% if form.password.errors %} {% for error in
          form.password.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">check</i>
          {{ form.confirm_password.label }} {{
          form.confirm_password(type="password", required=True) }} {% if
          form.confirm_password.errors %} {% for error in
          form.confirm_password.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">supervisor_account</i>
          {{ form.role.label }} {{ form.role(class="browser-default") }} {# Use
          browser-default for better styling control or initialize with JS #} {%
          if form.role.errors %} {% for error in form.role.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row center-align margin-bottom-large">
        <div class="col s6">
          <a
            href="{{ url_for('admin_users') }}"
            class="btn waves-effect waves-light btn-secondary btn-form z-depth-2"
            >Cancel</a
          >
        </div>
        <div class="col s6">
          {{ form.submit(class="btn waves-effect waves-light btn-coral btn-form
          z-depth-3") }}
        </div>
      </div>
    </form>
  </div>
</div>
{# Initialize Materialize Select if not using browser-default #} {#
<script>
  document.addEventListener("DOMContentLoaded", function () {
    var elems = document.querySelectorAll("select");
    var instances = M.FormSelect.init(elems, {});
  });
</script>
#} {% endblock %}
```

**`MyCookBook_v2/mycookbook/templates/admin_edit_user.html` (New File)**

```html
{% extends 'base.html' %} {% block content %}
<div class="container margin-top-large">
  <h1 class="secondary-heading uppercase center-align">
    Admin - Edit User: {{ user.username }}
  </h1>

  {% include "partials/toast_messages.html" %}

  <div class="row">
    <form
      method="POST"
      action="{{ url_for('admin_edit_user', user_id=user._id) }}"
      class="col s12 m8 offset-m2 l6 offset-l3 card-panel"
    >
      {{ form.hidden_tag() }}

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">person</i>
          {{ form.username.label(class="active") }} {# Add active class as field
          is pre-populated #} {{ form.username(required=True) }} {% if
          form.username.errors %} {% for error in form.username.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">email</i>
          {{ form.email.label(class="active") }} {{ form.email(type="email",
          required=True) }} {% if form.email.errors %} {% for error in
          form.email.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="input-field col s12">
          <i class="material-icons prefix">supervisor_account</i>
          {{ form.role.label }} {# Pre-select the role. Value passed from
          form(obj=user) handles this. #} {{ form.role(class="browser-default")
          }} {# Use browser-default or JS init #} {% if form.role.errors %} {%
          for error in form.role.errors %}
          <small class="text-red helper-text">{{ error }}</small>
          {% endfor %} {% endif %}
        </div>
      </div>

      {#
      <div class="row">
        <div class="col s12">
          <p><strong>Password Management:</strong></p>
          <p>
            <small
              >To reset a user's password, use the dedicated "Forgot Password"
              feature (if implemented) or provide a secure temporary password
              mechanism.</small
            >
          </p>
          {# Example: Add a button to trigger a password reset email (requires
          email setup) #} {#
          <a
            href="{{ url_for('admin_reset_password_request', user_id=user._id) }}"
            class="btn waves-effect waves-light orange"
            >Send Password Reset Link</a
          >
          #}
        </div>
      </div>
      #}

      <div class="row center-align margin-bottom-large">
        <div class="col s6">
          <a
            href="{{ url_for('admin_users') }}"
            class="btn waves-effect waves-light btn-secondary btn-form z-depth-2"
            >Cancel</a
          >
        </div>
        <div class="col s6">
          {{ form.submit(class="btn waves-effect waves-light btn-coral btn-form
          z-depth-3") }}
        </div>
      </div>
    </form>
  </div>
</div>
{# Initialize Materialize Select if not using browser-default #} {#
<script>
  document.addEventListener("DOMContentLoaded", function () {
    var elems = document.querySelectorAll("select");
    var instances = M.FormSelect.init(elems, {}); // Add options if needed
  });
</script>
#} {% endblock %}
```

**`MyCookBook_v2/mycookbook/templates/admin_users.html` (Modified)**

Add buttons/links to Add and Edit users.

```html
{% extends 'base.html' %} {% block content %}
<div class="container margin-top-large">
  <h1 class="secondary-heading uppercase center-align">Manage Users</h1>

  {% include "partials/toast_messages.html" %}

  <div class="row margin-bottom-large">
    <div class="col s12 center-align">
      <a
        href="{{ url_for('admin_add_user') }}"
        class="btn waves-effect waves-light btn-coral"
      >
        <i class="material-icons left">add</i>Add New User
      </a>
    </div>
  </div>

  <table class="striped centered responsive-table card-panel">
    {# Added card-panel for background #}
    <thead>
      <tr>
        <th>Username</th>
        <th>Email</th>
        <th>Role</th>
        <th>Password Set?</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for user in users %} {# Loop through users passed from the route #}
      <tr>
        <td>{{ user.username }}</td>
        <td>{{ user.email | default('N/A') }}</td>
        {# Display email, handle missing #}
        <td>{{ user.role | capitalize }}</td>
        {# Capitalize role #}
        <td>
          {% if user.password_set %}
          <i class="material-icons green-text">check_circle</i>
          {% else %}
          <i class="material-icons red-text">cancel</i>
          {% endif %}
        </td>
        <td>
          {# Edit Button #}
          <a
            href="{{ url_for('admin_edit_user', user_id=user._id) }}"
            class="btn-small waves-effect waves-light btn-green tooltipped"
            data-position="top"
            data-tooltip="Edit User {{ user.username }}"
          >
            <i class="fas fa-edit"></i>
          </a>

          {# Delete Button - Keep existing logic but ensure it's inside the loop
          #}
          <a
            href="{{ url_for('admin_delete_user', user_id=user._id) }}"
            onclick="return confirm('WARNING: Deleting user \'{{ user.username }}\' will also delete all their recipes. This cannot be undone. Are you sure?');"
            class="btn-small btn-red waves-effect waves-light tooltipped"
            data-position="top"
            data-tooltip="Delete User {{ user.username }}"
          >
            <i class="fas fa-trash-alt"></i>
          </a>
        </td>
      </tr>
      {% else %}
      <tr>
        <td colspan="5" class="center-align">No other users found.</td>
        {# Updated colspan #}
      </tr>
      {% endfor %}
    </tbody>
  </table>

  {# Optional: Display current admin info separately #} {% if current_admin_user
  %}
  <div class="margin-top-large">
    <h5 class="center-align">Current Admin User</h5>
    <p class="center-align">
      You are logged in as:
      <strong>{{ current_admin_user.username }}</strong> ({{
      current_admin_user.email }}) - Role: {{ current_admin_user.role |
      capitalize }}
    </p>
    <p class="center-align">
      <small>Admins cannot be edited or deleted from the list above.</small>
    </p>
  </div>
  {% endif %}
</div>
{% endblock %}
```

**Explanation:**

- **Forms:** Created `AdminAddUserForm` and `AdminEditUserForm` with necessary fields (username, email, password, role) and validators. Using `SelectField` for roles.
- **Routes:**
  - Added `/admin/add_user` route: Handles GET (show form) and POST (validate, check conflicts, hash password, insert user, redirect).
  - Added `/admin/edit_user/<user_id>` route: Handles GET (fetch user, pre-populate form) and POST (validate, check conflicts if username/email changed, update user, redirect). Includes checks to prevent admins editing themselves via this route.
  - Modified `admin_users`: Fetches users, potentially excluding the current admin from the main list for clarity.
  - Modified `admin_delete_user`: Added check for valid ObjectId, re-confirmed self-deletion prevention. Included recipe deletion logic based on original code/request.
  - All admin routes use the `@admin_required` decorator.
- **Templates:**
  - `admin_add_user.html`: Renders the add user form.
  - `admin_edit_user.html`: Renders the edit user form, pre-populated with user data.
  - `admin_users.html`: Displays the user table, includes links/buttons for "Add User", "Edit", and "Delete". Uses icons for better UX. Displays email and password set status.

**4. Create New Database Setup Script**

Finally, let's create the `initialize_database.py` script in the root directory.

**`MyCookBook_v2/initialize_database.py` (New File)**

```python
import os
import sys
from pymongo import MongoClient, errors
from werkzeug.security import generate_password_hash
import env # Import to load environment variables from env.py

# --- Configuration ---
MONGO_URI = os.environ.get("MONGO_URI")
DB_NAME = os.environ.get("MONGODB_NAME", "MyCookBook") # Default to MyCookBook if not set

# --- Check Configuration ---
if not MONGO_URI:
    print("ERROR: MONGO_URI environment variable not set.")
    print("Please ensure MONGO_URI is defined in your env.py file or environment.")
    sys.exit(1)
if not DB_NAME:
     print("ERROR: MONGODB_NAME environment variable not set.")
     print("Please ensure MONGODB_NAME is defined in your env.py file or environment.")
     sys.exit(1)


# --- Initial Data for Dropdowns ---
INITIAL_DATA = {
    "cuisines": [
        {"cuisine_type": "Italian"}, {"cuisine_type": "Mexican"},
        {"cuisine_type": "Vietnamese"}, {"cuisine_type": "Thai"},
        {"cuisine_type": "Indian"}, {"cuisine_type": "French"},
        {"cuisine_type": "American"}, {"cuisine_type": "Chinese"},
        {"cuisine_type": "Japanese"}, {"cuisine_type": "Spanish"},
        {"cuisine_type": "Greek"}, {"cuisine_type": "Other"},
    ],
    "meals": [
        {"meal_type": "Breakfast"}, {"meal_type": "Lunch"},
        {"meal_type": "Dinner"}, {"meal_type": "Dessert"},
        {"meal_type": "Snack"}, {"meal_type": "Appetizer"},
        {"meal_type": "Side Dish"}, {"meal_type": "Soup"},
    ],
    "diets": [
        {"diet_type": "Vegetarian"}, {"diet_type": "Vegan"},
        {"diet_type": "Gluten-Free"}, {"diet_type": "Keto"},
        {"diet_type": "Paleo"}, {"diet_type": "Pescatarian"},
        {"diet_type": "Low-Carb"}, {"diet_type": "Dairy-Free"},
        {"diet_type": "None"},
    ]
}

# --- Collections to Ensure Exist ---
COLLECTIONS = ["users", "recipes", "cuisines", "diets", "meals"]

# --- Optional Default Admin User ---
CREATE_ADMIN = True # Set to False to skip admin creation
ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "admin@example.com" # Change this email
ADMIN_PASSWORD = "password" # !!! CHANGE THIS IMMEDIATELY AFTER RUNNING !!!

def initialize_database():
    """Connects to MongoDB, optionally drops DB, creates collections,
       populates dropdown data, and optionally creates a default admin."""

    print(f"--- Starting Database Initialization for '{DB_NAME}' ---")

    try:
        print(f"Connecting to MongoDB at: {MONGO_URI.split('@')[-1].split('/')[0]}...") # Mask credentials in URI printout
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000) # Increased timeout
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        print("MongoDB connection successful!")
        db = client[DB_NAME]
    except errors.ConnectionFailure as e:
        print("\nERROR: MongoDB Connection Failed.")
        print("Details:", e)
        print("\nPlease check:")
        print("1. Your MONGO_URI in env.py is correct.")
        print("2. MongoDB Atlas IP Whitelist includes your current IP address.")
        print("3. Your internet connection is stable.")
        sys.exit(1)
    except Exception as e:
         print(f"\nERROR: An unexpected error occurred during connection: {e}")
         sys.exit(1)

    # --- Optional: Drop Database ---
    # Uncomment the following lines ONLY if you want to completely reset the database.
    # WARNING: This will permanently delete all data in the database!
    # confirm_drop = input(f"WARNING: Are you sure you want to DROP the database '{DB_NAME}'? (yes/no): ")
    # if confirm_drop.lower() == 'yes':
    #     print(f"Dropping database '{DB_NAME}'...")
    #     client.drop_database(DB_NAME)
    #     print(f"Database '{DB_NAME}' dropped.")
    #     db = client[DB_NAME] # Re-reference the database after dropping
    # else:
    #     print("Database drop cancelled.")

    # --- Ensure Collections Exist ---
    print("\nEnsuring collections exist...")
    existing_collections = db.list_collection_names()
    for coll_name in COLLECTIONS:
        if coll_name not in existing_collections:
            try:
                db.create_collection(coll_name)
                print(f"- Created collection: '{coll_name}'")
            except errors.CollectionInvalid:
                 print(f"- Collection '{coll_name}' already exists (or concurrent creation).")
            except Exception as e:
                 print(f"ERROR: Failed to create collection '{coll_name}': {e}")
        else:
            print(f"- Collection '{coll_name}' already exists.")

    # --- Populate Dropdown Collections ---
    print("\nPopulating dropdown collections (cuisines, meals, diets)...")
    for coll_name, data_list in INITIAL_DATA.items():
        if coll_name in db.list_collection_names():
            collection = db[coll_name]
            key_field = list(data_list[0].keys())[0] # Assumes first key is unique identifier
            upserted_count = 0
            errors_count = 0
            for item in data_list:
                try:
                    result = collection.update_one(
                        {key_field: item[key_field]},
                        {"$set": item},
                        upsert=True
                    )
                    if result.upserted_id:
                        upserted_count += 1
                except Exception as e:
                    print(f"  ERROR adding/updating item in '{coll_name}': {item}. Error: {e}")
                    errors_count += 1
            print(f"- '{coll_name}': Added {upserted_count} new items. {errors_count} errors encountered.")
        else:
            print(f"ERROR: Collection '{coll_name}' not found for data population.")


    # --- Optional: Create Default Admin User ---
    if CREATE_ADMIN:
        print("\nCreating default admin user...")
        users_collection = db["users"]
        # Check if admin username or email already exists
        existing_admin = users_collection.find_one({
            "$or": [{"username": ADMIN_USERNAME}, {"email": ADMIN_EMAIL}]
        })

        if existing_admin:
            print(f"- Admin user '{ADMIN_USERNAME}' or email '{ADMIN_EMAIL}' already exists. Skipping creation.")
        else:
            try:
                hashed_password = generate_password_hash(ADMIN_PASSWORD)
                admin_user = {
                    "username": ADMIN_USERNAME,
                    "email": ADMIN_EMAIL,
                    "password": hashed_password,
                    "role": "admin",
                    "password_set": True,
                    "user_recipes": []
                    # "created_at": datetime.utcnow()
                }
                users_collection.insert_one(admin_user)
                print(f"- Default admin user '{ADMIN_USERNAME}' created successfully.")
                print("\n" + "="*40)
                print("  IMPORTANT SECURITY WARNING!")
                print(f"  Default admin password is '{ADMIN_PASSWORD}'.")
                print("  CHANGE THIS PASSWORD IMMEDIATELY after logging in.")
                print("="*40 + "\n")
            except Exception as e:
                print(f"ERROR: Failed to create default admin user: {e}")

    print("--- Database Initialization Complete ---")
    client.close()
    print("MongoDB connection closed.")

if __name__ == "__main__":
    initialize_database()
```

**How to Run the Setup Script:**

1.  Save the code above as `initialize_database.py` in the root of your `MyCookBook_v2` project directory (the same level as `run.py` and `env.py`).
2.  Make sure your `env.py` file has the correct `MONGO_URI` and `MONGODB_NAME`.
3.  Open your terminal, navigate to the `MyCookBook_v2` directory.
4.  Run the script using: `python initialize_database.py`
5.  Follow any prompts (especially if you uncomment the database drop section).
6.  **Crucially, if the admin user is created, log in immediately and change the default password.**

This completes all the requested features and fixes. Remember to install any new dependencies if necessary (though it seems only standard libraries and existing ones were used). Test thoroughly after applying these changes.
