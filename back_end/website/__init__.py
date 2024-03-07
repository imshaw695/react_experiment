# This is inspired by the article here:
# https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xv-a-better-application-structure
# https://medium.com/@lyle-okoth/how-to-deploy-a-production-grade-flask-application-to-an-aws-ec2-instance-using-github-actions-6241886b197
print("before first imports")
import platform
import os
import socket
import logging
from website.utilities import addLoggingLevel
from website.multi_factor_authentication.Multi_factor import Multi_factor
from website.get_bad_password_set import get_bad_password_set
from flask import Flask
from flask_mail import Mail

# from flask_mail import Mail

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_talisman import Talisman
# instantiate the migrate for initialisation with app and db later
# to create the files and fiolders in the first instance, you need to
# execute "flask db init" from the conda command window in the project top level directory
migrate = Migrate()

# instantiate db for initialisation with app later
db = SQLAlchemy()

# create the holder for site config stuff
site_config = {}
site_config["platform"] = platform.system()
site_config["base_directory"] = os.path.abspath(os.path.dirname(__file__))
site_config["host_name"] = socket.gethostname()
site_config[
    "environment"
] = f'host:{site_config["host_name"]}, platform:{site_config["platform"]}'
site_config["INSTANCE_TYPE"] = os.environ.get("INSTANCE_TYPE")
site_config["this_url"] = os.environ.get("this_url")

multi_factor = Multi_factor(url=site_config["this_url"]) 

mail = Mail() 

bad_password_set = get_bad_password_set()

print("about to define create_app")
def create_app():
    print("now running create_app")
    # Create Flask application.
    this_directory = os.path.abspath(os.path.dirname(__file__))
    static_folder = os.path.join(this_directory, "templates", "static")
    print(static_folder)
    app = Flask(
        __name__,
        instance_relative_config=False,
        static_folder=static_folder,
        static_url_path="/static",
    )
    try:
        app.config.from_object("config.Config")
    except Exception as err:
        print(f'On line 54 the error is {err}')
    # print("on line 55")

    with app.app_context():
        addLoggingLevel('CRUD', logging.INFO + 1)
        SELF = "'self'"
        csp = {
            "default-src": "'self'",
            "img-src": [
                "*"        
                        ],
            "media-src": [
                "vimeo.com",
            ],
            'connect-src': [
                SELF,
                "vimeo.com",
            ],
            'frame-src' : [
                'player.vimeo.com' 
            ],
            'style-src' : [
            SELF,
            '\'unsafe-inline\''
            ]
        }
        # now all the initiations

        # Security headers, forcing https by default
        # talisman = Talisman(app, content_security_policy=csp)

        db.init_app(app)
        migrate.init_app(app, db=db)
        mail.init_app(app)
        app.extensions['mail'].debug = 0

        # import the routes
        from website import routes
        # print("on line 91, routes was imported")
        
        # set up logging to data base
        from website.Sql_alchemy_log_handler import Sql_alchemy_log_handler
        sql_alchemy_log_handler = Sql_alchemy_log_handler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        sql_alchemy_log_handler.setFormatter(formatter)
        app.logger.addHandler(sql_alchemy_log_handler)

        # set the log level dependent on the environment
        if site_config["INSTANCE_TYPE"] in ["production"]:
            app.logger.setLevel(logging.INFO)
        else:
            app.logger.setLevel(logging.DEBUG)

        app.logger.info("[INITIALISING] Starting the web application") 

        # all is set up correctly so return the app
        return app
