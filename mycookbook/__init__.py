import os
from flask import Flask
from flask_pymongo import PyMongo
from authlib.integrations.flask_client import OAuth 
if os.path.exists("env.py"):
    import env


app = Flask(__name__)
# Config Settings & Environmental Variables located in env.py
app.config['MONGODB_NAME'] = "MyCookBook"
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# Khởi tạo OAuth
oauth = OAuth(app)

# Đăng ký Google OAuth client
oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    claims_options={
        'iss': {
            'essential': True,
            'values': ['https://accounts.google.com', 'accounts.google.com']
        }
    }
)
mongo = PyMongo(app)
'''
The following import has to be located at the bottom of the file,
as it needs to import routes after the app has been initialised
to prevent circular imports.
'''
from mycookbook import routes
