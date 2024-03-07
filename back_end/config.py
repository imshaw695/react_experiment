# Use in conjucntion with a .env file
# format of the .env is plain text with lines as follows

import datetime
# Class-based Flask app configuration
import os
from dotenv import load_dotenv

this_directory = os.path.abspath(os.path.dirname(__file__))
print(f"in config.py and this_directory: {this_directory}")
load_dotenv(os.path.join(this_directory, '.env'),override=True)

class Config:
    # 
    # first the safe ones that we know the answer to
    # 
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # The application entry point
    FLASK_APP = 'wsgi.py'

    # 
    # Now the secret and machine specific ones from environment variables - see .env
    # 
    SECRET_KEY = os.environ.get('SECRET_KEY')
    INSTANCE_TYPE = os.environ.get('INSTANCE_TYPE')
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))
    DB_USERNAME = os.environ.get('DB_USERNAME')
    database_password = os.environ.get('database_password')
    database_url = os.environ.get('database_url')
    database_port = os.environ.get('database_port')
    database = os.environ.get('database')
    DB_TYPE = os.environ.get('DB_TYPE')

    # And the dependant on environment variables
    # We don't need the if statement
    # We left it here to show how you can create the database connection string based on the environment variable set in .env file

    # Create the db connection string
    # The final line keeps compatibility between 5.7 and 8.x
    # set db uri based on db type
    if DB_TYPE == "mysql":
        SQLALCHEMY_DATABASE_URI = (
            "mysql+mysqlconnector://"
            + DB_USERNAME
            + ":"
            + database_password
            + "@"
            + database_url
            + ":" + database_port
            + "/"
            + database
            + "?charset=utf8mb4&collation=utf8mb4_general_ci"
        )
    
    if DB_TYPE == "postgresql":
            SQLALCHEMY_DATABASE_URI = (
            "postgresql://"
            + DB_USERNAME
            + ":"
            + database_password
            + "@"
            + database_url
            + ":" + database_port
            + "/"
            + database
        )
    # This option is specifically for PythonAnyWhere as the mysql db drops connections that are 300 seconds old
    # Inspired from here: https://stackoverflow.com/questions/56271116/flask-sqlalchemy-sqlalchemy-engine-options-not-set-up-correctly
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 240,
        'pool_pre_ping': True
    }

    support_user_email = os.environ.get('support_user_email')
    support_user_password = os.environ.get('support_user_password')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_SERVER = "smtp.office365.com"
    MAIL_PORT = "587"
    MAIL_USE_TLS = True
    MAIL_USERNAME = support_user_email
    ADMINS = [support_user_email]


    # move the location of the staic folder for vue / vite 
    print(this_directory)
    STATIC_FOLDER = os.path.join(this_directory, "website", "templates", "static")
    static_folder = os.path.join(this_directory, "website", "templates", "static")
    STATIC_URL_PATH = "/staticx"

if __name__ == "__main__":

    # test to see that config is working 
    config = Config()
    keys = config.__dir__()
    for key in keys:
        if key[0:2] != "__":
            value = config.__getattribute__(key)
            if isinstance(value, str):
                print(f"key: {key}    value: {value}")