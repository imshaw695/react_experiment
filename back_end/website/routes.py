from flask import Flask, jsonify, request, render_template, make_response, render_template_string, url_for
from flask import current_app as app
from website import multi_factor
import sqlalchemy
from sqlalchemy.orm import class_mapper
from sqlalchemy.sql import func, expression, and_
import os
import secrets
import datetime
import time
import re
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from website import db, site_config, bad_password_set, mail

from website.models import Log, Role, User
Models = dict(
    Role=Role,
    User=User,
    Log=Log
)

try:
    SESSION_EXPIRES_SECONDS = int(os.environ.get("SESSION_EXPIRES_SECONDS"))
except:
    SESSION_EXPIRES_SECONDS = 180

route_timings = {}

def computed_operator(column, v):

    # needed for building dynamic filters
    # adapted from here https://stackoverflow.com/a/69331512/2508957
    # eg:
    # name = "Ariel"
    # for boolean fields such as is_deleted, use:
    # is_deleted = "1"
    # is_deleted = "0"
    if re.match(r"^!", v):
        """__ne__"""
        val = re.sub(r"!", "", v)
        return column.__ne__(val)
    if re.match(r">(?!=)", v):
        """__gt__"""
        val = re.sub(r">(?!=)", "", v)
        return column.__gt__(val)
    if re.match(r"<(?!=)", v):
        """__lt__"""
        val = re.sub(r"<(?!=)", "", v)
        return column.__lt__(val)
    if re.match(r">=", v):
        """__ge__"""
        val = re.sub(r">=", "", v)
        return column.__ge__(val)
    if re.match(r"<=", v):
        """__le__"""
        val = re.sub(r"<=", "", v)
        return column.__le__(val)
    if re.match(r"(\w*),(\w*)", v):
        """between"""
        a, b = re.split(r",", v)
        return column.between(a, b)
    """ default __eq__ """
    return column.__eq__(v)



@app.route("/", methods=["GET"])
@app.route("/index", methods=["GET"])
def home():
    return render_template("index.html")

# This API will take requests from the front end and create a user in the DB, if done correctly.
@app.route("/api_create_user_db", methods=["POST"])
def api_create_user_db():

    # [STANDARD BLOCK] first create a guard barrier such that only authenticated users can pass
    user = get_user_from_request(request)
    if not user["logged_in"]:
        # I previously logged this situation but it henerates many false problems.
        # The serious ones are logged by get_user_from_request
        return dict(
            rc=16,
            message=f"You do not have the correct authorisation for this api",
        )

    # define the operation
    operation = "create"

    try:
        # get the contents of the package
        api_package = request.get_json()
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (1)",
        )

    try:
        # we must have a model_name with a model
        model_name = "User"
        Model = Models[model_name]
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (2)",
        )

    try:
        data = api_package["data"]
        new_user_role = api_package["role"]
        create_package = data["create_package"]
        temporary_id = create_package["id"]

    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (2)",
        )
    
    results = Role.query.all()
    roles = []
    for result in results:
        record = result.get_dict()
        roles.append(record)

    for role in roles:
        if role["name"] == user["role_name"]:
            user_role = role
    # Check to make sure they have permission to create user of this role level
    if new_user_role["level"] >= user_role["level"]:
        return dict(
            rc=16,
            message=f"User attempted to create a user of a higher level.",
        )

    # Generate a secure throw away password as we never accept a user entered password on create_user
    password = ""
    while not is_strong_enough(password):
        password = secrets.token_urlsafe(20)
    create_package["hashed_password"] = generate_password_hash(password)

    # Now I have the full create package, need to see if the creating user has authority to do this
    # does this user have authority
    if not Model.is_user_authorised(user, operation, create_package):
        app.logger.warning(
            f"[ACCESS] The user {user} tried to create a user without sufficient authority"
        )
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"You don't have sufficient authority to perform the {operation}",
        )

    # if we are here, then we are good to go
    try:
        # need to make sure that the user does not create a user with a higher role_name than themselves
        new_record = Model()
        new_record.update_from_dictionary(create_package)
        db.session.add(new_record)
        db.session.commit()
        # knock the pii data out of the crud log
        created_record = new_record.get_dict()
        create_package["email"] = created_record["email"]
        create_package["name"] = created_record["name"]
        create_package["password"] = "Encrypted"
        app.logger.crud(
            f"[CREATE] user_email:{user['email']} created a {model_name} the following record: \n{create_package}"
        )

        # add the original id
        created_record["temporary_id"] = temporary_id
        return dict(
            rc=0, message=f"The {model_name} was added", created_record=created_record
        )
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        db.session.rollback()
        db.session.flush()  # for resetting non-commited .add()
        return dict(rc=16, message=f"The {model_name} was not added")

# After successful login, this method will send user data and jwt to the front end.
def get_logged_in_package(user, ip_address):

    package = {}
    package["ip_address"] = ip_address

    if type(user) == type({}):

        user = User.get_user_by_email(user["email"])

        you_can_break_here = True

    user = user.get_dict()

    # now get the role_name
    role = Role.query.filter_by(id=user["role_id"]).first()
    user["role_name"] = role.name

    seconds = SESSION_EXPIRES_SECONDS

    loggedOnAt = datetime.datetime.now(tz=datetime.timezone.utc)
    jwt_content = dict(
        exp=loggedOnAt + datetime.timedelta(seconds=seconds),
        email=user["email"],
        role_name=user["role_name"],
        ip_address=ip_address,
        loggedOnAtSeconds=loggedOnAt.timestamp(),
    )
    session_jwt = jwt.encode(jwt_content, app.secret_key, algorithm="HS512")
    package["session_jwt"] = session_jwt
    package["logged_in"] = True
    package["id"] = user["id"]
    package["name"] = user["name"]
    package["email"] = user["email"]
    package["role_name"] = user["role_name"]
    package["role_id"] = user["role_id"]
    package["failed_login_streak"] = user["failed_login_streak"]

    return package



@app.route("/api_login", methods=["POST"])
# Now comes the actual function definition for processing this page
def api_login():

    package = {}
    package["session_jwt"] = ""
    package["email"] = ""
    package["password"] = ""
    package["password_authorised"] = False
    package["mfa_authorised"] = False
    package["ip_address"] = ""
    package["mfa_jwt"] = ""
    package["session_jwt"] = ""

    try:
        api_package = request.get_json()
        form_password = api_package["password"]
        form_email = api_package["email"].lower()
        ip_address = api_package["ip_address"].lower()
        mfa_jwt = api_package["mfa_jwt"]

    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        return dict(
            rc=16,
            message=f"You did not enter the correct details to log in with",
            user=package,
        )

    # now lets try from the database
    user = User.get_user_by_email(form_email)

    # If no match just get straight out
    if not user:
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"Login failed - no user on db",
            user=package,
        )

    # have we exceeded the failed login streak count
    if user.failed_login_streak > 0:
        you_can_break_here = True
    if user.failed_login_streak > 10:
        app.logger.warning(
            f"[ACCESS] A user with the following email: {user.email} attempted to log in more than 10 times with the wrong password "
        )
        package["failed_login_streak"] = user.failed_login_streak
        return dict(
            rc=16,
            message=f"Login failed - account locked. Please email support to ask for a call back on:{app.config['ADMINS'][0]}",
            user=package,
        )

    password_good = False
    try:
        if check_password_hash(user.hashed_password, form_password):
            password_good = True

        else:
            # throttle it
            # We need to do a throttle here that will not block the whole flask process

            # increase the streak count
            user.failed_login_streak = user.failed_login_streak + 1
            package["failed_login_streak"] = user.failed_login_streak

            try:
                db.session.commit()
            except Exception as err:
                app.logger.exception(f"[EXCEPTION] err was {err}")

            return dict(
                rc=16,
                message=f"Login failed - incorrect authentication",
                user=package,
            )

    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        return dict(
            rc=16,
            message=f"Login failed 3 ",
            user=package,
        )
        # throttle it
        # We need to do a throttle here that will not block the whole flask process

    # We can only get to here if the password is good
    user.failed_login_streak = 0

    logged_in_package = get_logged_in_package(user, ip_address)
    logged_in_package["password_authorised"] = True

    # First we need to see if we have a confirmed mfa_secret on the users record
    logged_in_package["mfa_secret_confirmed"] = user.mfa_secret_confirmed
    if not user.mfa_secret_confirmed:
        # get the secret and the qr code
        mfa_secret, mfa_qr_image = multi_factor.get_secret_and_image(form_email)
        mfa_qr_image = mfa_qr_image.tolist()
        print(f"In api_login and mfa_secret just created as: {mfa_secret}")

        # must use update_from_dictionary as it is secure data that must be encrypted
        # (it gets stored in the jwt to check on validation that the mfa_secret is the same)
        update_dictionary = dict(mfa_secret=mfa_secret)
        user.update_from_dictionary(update_dictionary)
    else:
        mfa_qr_image = []

    # finally, do the mfa_jwt check
    logged_in_package["mfa_authorised"] = False
    try:
        decoded_mfa_jwt = jwt.decode(mfa_jwt, app.secret_key, algorithms="HS512")
        if (
            (decoded_mfa_jwt["ip_address"] == ip_address)
            and (decoded_mfa_jwt["email"] == form_email)
            and decoded_mfa_jwt["mfa_secret_encrypted"] == user.mfa_secret
        ):
            logged_in_package["mfa_authorised"] = True
        else:
            logged_in_package["mfa_authorised"] = False
            logged_in_package["logged_in"] = False
    except Exception as err:
        logged_in_package["mfa_authorised"] = False
        logged_in_package["logged_in"] = False

    try:
        db.session.commit()
        db.session.flush()
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")

    return dict(
        rc=0,
        message="Login was successful",
        user=logged_in_package,
        mfa_qr_image=mfa_qr_image,
    )

# This API can delete records from any table, if the correct model name is provided.
@app.route("/api_delete_record_db", methods=["POST"])
def api_delete_record_db():

    # [STANDARD BLOCK] first create a guard barrier such that only authenticated users can pass
    user = get_user_from_request(request)
    if not user["logged_in"]:
        # I previously logged this situation but it henerates many false problems.
        # The serious ones are logged by get_user_from_request
        return dict(
            rc=16,
            message=f"You do not have the correct authorisation for this api",
        )

    # define the operation
    operation = "delete"

    try:
        # get the contents of the package
        api_package = request.get_json()
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (1)",
        )

    try:
        # we must have a model_name with a model
        model_name = api_package["model_name"]
        Model = Models[model_name]
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (2)",
        )

    # does this user have authority
    if not Model.is_user_authorised(user, "delete"):
        app.logger.critical(
            f"[CRITICAL] User with user.id {user} attempting to delete records from {model_name}"
        )
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"You don't have sufficient authority to perform the {operation}",
        )

    # If we get to here then we are good to execute the operation

    # api_package contains a dictionary called delete_package:
    # model = "User"
    # data = {dict with id that needs deleting}

    # return a package:
    # rc = integer return code [0 means ok, 4 means not applied]
    # message_text = "A user facing message suitable to be displayed on th screen "
    # message_category = "success" or "warning" or "danger"

    if not "data" in api_package:
        app.logger.warning(
            f"[WARNING] User with user.id {user} attempting to delete records from {model_name}"
        )
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message_text=f"There was a serious error and the record {operation} was not succesful",
            message_category="danger",
        )
    else:
        data = api_package["data"]

    if not "delete_package" in data:
        app.logger.warning(
            f"[WARNING] User with user.id {user} attempting to delete records from {model_name}"
        )
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message_text=f"There was a serious error and the record {operation} was not succesful",
            message_category="danger",
        )
    else:
        delete_package = data["delete_package"]

    # this operation requires an id
    try:
        id = int(delete_package["id"])
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message_text=f"There was a serious error and the record {operation} was not succesful",
            message_category="danger",
        )

    # get the record to we need
    record_to_delete = Model.query.filter_by(id=id).first()

    # check we got a valid record
    if record_to_delete.id == id:
        Model.query.filter_by(id=id).delete()

        record_to_delete.is_deleted = True

        try:
            db.session.commit()
            app.logger.crud(
                f"[DELETE] user_email:{user['email']} deleted a {model_name} the following record: \n{delete_package}"
            )
            return dict(rc=0, message=f"The {model_name} was deleted")
        except Exception as err:
            app.logger.exception(f"[EXCEPTION] err was {err}")
            db.session.rollback()
            db.session.flush()  # for resetting non-commited .add()
            app.logger.exception(f"[EXCEPTION] err was {err}")
            return dict(
                rc=16,
                message=f"There was a serious error and the record {operation} was not succesful",
            )

    else:
        app.logger.warning(
            f"[WARNING] User with user.id {user} attempting to delete records from {model_name}"
        )
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"There was a serious error and the record {operation} was not succesful",
        )


@app.route("/api_reset_password_request", methods=["POST"])
def api_reset_password_request():

    # this triggers an email to be sent to the user
    # we can throttle responses as it requires no immediate feedback

    try:
        api_package = request.get_json()
        if "email" in api_package:
            email = api_package["email"].lower()
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(rc=16, message="No email arrived, try again")

    # user = User.query.filter_by(email=email).first()
    user = User.get_user_by_email(email)

    if user:
        try:
            send_password_reset_email(user)
        except Exception as err:
            app.logger.exception(f"[EXCEPTION] err was {err}")

    else:
        # we should put a warning out at least in case we are being swamped
        app.logger.warning(
            f"[WARNING] User with email: {email} attempting a password reset to a non existent email. If there are many of these, an attack could be underway"
        )

    return dict(
        rc=0,
        message="If that email address is registered, then a reset email has been sent to it",
    )



@app.route("/api_reset_password/", methods=["POST"])
def api_reset_password():

    """
    Arrive here via two possible routes:

        The user clicks on an email link with a token and it must serve the reset_password page in vue
        that must then call this api route with a new password
        It's low volume in normal circumstances

        or

        The user chooses reset passwaird from the navbar and is already signed in

    """

    # get the api_package and passwords that I will need whichever way it goes
    try:
        api_package = request.get_json()
        password_1 = api_package["input"]["password_1"]
        password_2 = api_package["input"]["password_2"]
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        return dict(
            rc=16,
            message="The request was not formed correctly, try again",
        )

    # see if the passwords are the same
    if not password_1 == password_2:
        return dict(rc=4, message=f"The passwords do not match")

    # see if the passwords are good enough
    if not is_strong_enough(password_1):
        return dict(rc=4, message=f"The password does not have sufficient complexity")

    # see if they are logged in
    user = get_user_from_request(request)

    # Get the user_model from the token or because I am logged on
    if user["logged_in"]:
        user_model = User.get_user_by_email(user["email"])
    else:

        # still might be ok if there is a token
        try:
            password_reset_token = api_package["input"]["password_reset_token"]

            # see if the token is valid
            user_id = User.verify_token(
                password_reset_token, token_purpose="reset_password"
            )

            # get the user from the db

            if user_id:
                user_model = User.query.get(user_id)
            else:
                return dict(rc=4, message=f"The password was not updated")

        except Exception as err:
            app.logger.warning(
                f"[ACCESS] Attempt to access {request.path} with no valid credentials. Could be an attack"
            )
            return dict(
                rc=16,
                message=f"You do not have the correct authorisation for this",
            )

    # If I get to here then I am logged in or I have a valid token
    # and we have the user_model

    try:
        user_model.set_password(password_1)
        db.session.commit()
        app.logger.crud(
            f"[UPDATE] user_id:{user_model.id} updated a User record to change the password"
        )
        return dict(rc=0, message=f"Password changed successfully")
    except Exception as err:
        db.session.rollback()
        db.session.flush()  # for resetting non-commited .add()
        app.logger.exception(f"[EXCEPTION] err was {err}")
        return dict(rc=4, message=f"The password was not updated")



@app.route("/api_check_mfa_authenticator_code", methods=["POST"])
# Now comes the actual function definition for processing this page email
def api_check_mfa_authenticator_code():

    # todo: Throttling if it fails
    try:
        # get the contents of the package
        api_package = request.get_json()
        ip_address = api_package["ip_address"].lower().strip()
        mfa_authenticator_code = api_package["mfa_authenticator_code"]
        session_jwt = api_package["session_jwt"]
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            user=dict(logged_in=False),
            rc=16,
            message=f"The api request was badly formed - please try  again ",
        )

    user = get_user_from_request(request)

    try:
        # This has been failing if the user leaves the mfa digits waiting for more than 1 hour 
        # get the mfa_secret - needs to be two stage as mfa_secret is pii encrypted
        user_from_db_via_orm = User.get_user_by_email(user["email"])
        user_as_dictionary = user_from_db_via_orm.get_dict()
        mfa_secret = user_as_dictionary["mfa_secret"]
    except:
        return dict(
            user=dict(logged_in=False),
            rc=16,
            message=f"The api request was badly formed - please try  again ",
        )


    # PBS: There have been some difficult to explain situations where the code cannot be authenticated using the digits from the 
    # authenticator app
    # One possible explanation for this is that the orm and the db are out of synch 
    # After research, it seems highly unlikely but I find it difficult to rule out
    # This route will get the data from both sources and if not identical, it will throw a log event 
    sql = "select * from users where id = :user_id"
    sql = sqlalchemy.text(sql)

    # now bind the parameters to the text clause object
    try:
        parameters = dict(user_id=user_from_db_via_orm.id)
        sql = sql.bindparams(**parameters)
        user_from_db_via_sql = db.session.execute(sql).first()

        if (not user_from_db_via_sql.mfa_secret == user_from_db_via_orm.mfa_secret):

            # This is an extremely serious situation 
            app.logger.critical(f"[DB SYNCH ERROR] {user_as_dictionary['email']} Has a different mfa_secret when accessed through the orm: [{user_from_db_via_orm.mfa_secret}] compared to direct from db: [{user_from_db_via_sql.mfa_secret}] (both pii encrypted)")
            pass

    except Exception as err:
        pass

    # get the correct response
    mfa_correct_response = multi_factor.get_current_otp(mfa_secret)

    if mfa_authenticator_code == mfa_correct_response:
        seconds = 365 * 24 * 60 * 60
        loggedOnAt = datetime.datetime.now(tz=datetime.timezone.utc)
        jwt_content = dict(
            exp=loggedOnAt + datetime.timedelta(seconds=seconds),
            email=user["email"],
            ip_address=ip_address,
            mfa_secret_encrypted=user_from_db_via_orm.mfa_secret,
        )
        mfa_jwt = jwt.encode(jwt_content, app.secret_key, algorithm="HS512")
        rc = 0
        if not user_from_db_via_orm.mfa_secret_confirmed:
            user_from_db_via_orm.mfa_secret_confirmed = True
            try:
                db.session.commit()
                db.session.flush()
            except:
                rc = 12
                app.logger.exception(
                    f"[EXCEPTION] during save of mfa secret confirmation err was {err}"
                )
    else:
        mfa_jwt = False
        rc = 4

    return dict(rc=rc, message=f"The ip_address_package is attached", mfa_jwt=mfa_jwt)


# API for getting data from tables
@app.route("/api_get_records_db", methods=["POST"])
def api_get_records_db():

    time_started = time.time()

    # [STANDARD BLOCK] first create a guard barrier such that only authenticated users can pass
    user = get_user_from_request(request)
    if not user["logged_in"]:
        # The serious ones are logged by get_user_from_request
        return dict(
            rc=16,
            message=f"You do not have the correct authorisation for this api",
        )

    # define the operation
    operation = "read"

    try:
        # get the contents of the package
        api_package = request.get_json()
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (1)",
            records=[],
        )

    try:
        # we must have a model_name with a model
        model_name = api_package["model_name"]

        Model = Models[model_name]
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (2)",
            records=[],
        )
    
    # does this user have authority
    if not Model.is_user_authorised(user, operation):
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"You don't have sufficient authority to perform the {operation}",
            records=[],
        )

    if model_name == "User":
        users = User.query.filter(User.id > 0).all()
        
        users_list = []
        for user in users:
            user_dict = user.get_dict()
            users_list.append(user_dict)

        return users_list

    try:
        data = api_package["data"]
        filter_package = data["filter_package"]
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")
        # throttle it
        # We need to do a throttle here that will not block the whole flask process
        return dict(
            rc=16,
            message=f"The api request was badly formed - please try the {operation} again (2)",
            records=[],
        )

    # if we are here, then we are good to go
    query = Model.query
    filters = []
    for column_name, column_criteria in filter_package.items():
        mapper = class_mapper(Model)
        if not hasattr(mapper.columns, column_name):
            continue
        filters.append(
            computed_operator(mapper.columns[column_name], f"{column_criteria}")
        )

    query = query.filter(*filters)
    results = query.all()
    records = []
    for result in results:
        record = result.get_dict()
        records.append(record)

    gather_and_log_response_times(f"api_get_records_db [{model_name}]", time_started)

    return dict(
        rc=0,
        message=f"",
        records=records,
    )

# This api takes the encoded jwt and checks the expiry
@app.route("/api_check_jwt", methods=["POST"])
def api_check_jwt():
    api_package = request.get_json()

    if not api_package or not api_package.get('token'):
    # returns 401 if any email or / and password is missing
        return dict(
            message='No token provided.',
            rc=16,
            type="danger"
        )
    
    jwt_encoded = api_package["token"]
    try:
        jwt_decoded = jwt.decode(jwt_encoded, app.config['SECRET_KEY'], algorithms='HS512')
        # token not expired?
        status="valid"
        # time_remaining = jwt_decoded["exp"] - datetime.utcnow().timestamp()
        # time_remaining = time_remaining / 60 
        # if time_remaining < 1:
        #     message = f'Warning: Less than one minute before session expires.'
        #     return dict(
        #         status=status,
        #         rc=0,
        #         type='danger',
        #         message=message
        #     )
        return dict(
            status=status,
            rc=0
        )

        # need to find a way to determine time remaining and include it in the dict
    except jwt.exceptions.ExpiredSignatureError:
        # token expired
        status="invalid"
        return dict(
            status=status,
            rc=16,
            message="Session expired, please login.",
            type="danger"
        )


@app.route("/api_test_critical_log")
def test_critical_log(time_it=True):

    # throttle it
    # We need to do a throttle here that will not block the whole flask process

    # now fall over after logging a critical event
    try:
        1 / 0
    except Exception as err:
        app.logger.exception(f"[EXCEPTION] err was {err}")

    return dict(rc=16, message="A criticial error was forced as part of a test")


@app.errorhandler(404)
# inbuilt function which takes error as parameter
def not_found(e):
    # defining function
    return render_template("index.html")

def get_user_from_request(request, refresh_session_jwt=False, mfa_required=True):

    # Every api needs a legitimiate user to be signed in and to have a
    # properly encoded jwt
    # If the jwt is missing or invalid (other than being timed out) then
    # the reponse is throttled with a 1 second sleep

    """
    There are further enhancement that we can do to improve security
    1   Always verify this is a POST request and discard anything that is not
    2   Verify the source origin and the target origin match
    todo: further investigate and deploy if suitable
    """

    api_package = request.get_json()

    user = dict(logged_in=False, role_name=None)

    # make sure we have a session and a mfa jwt - bounce if not
    try:
        session_jwt = api_package["session_jwt"]
        decoded_session_jwt = jwt.decode(
            session_jwt, app.secret_key, algorithms="HS512"
        )
        user_from_db_via_orm = User.get_user_by_email(decoded_session_jwt["email"])

    except Exception as err:
        return user

    # If we have come from api_get_user, we must bounce if we don't have a valid mfa_jwt
    if request.endpoint == "api_get_user":
        try:
            mfa_jwt = api_package["mfa_jwt"]
            decoded_mfa_jwt = jwt.decode(mfa_jwt, app.secret_key, algorithms="HS512")

            # now check that this user has the correct email address
            if not decoded_mfa_jwt["email"] == decoded_session_jwt["email"]:
                return dict(logged_in=False, role_name=None)

            if not decoded_mfa_jwt["ip_address"] == decoded_session_jwt["ip_address"]:
                return dict(logged_in=False, role_name=None)

            if not decoded_mfa_jwt["mfa_secret_encrypted"] == user_from_db_via_orm.mfa_secret:
                return dict(logged_in=False, role_name=None)

            # If we get to here then the frequent check on the user is ok as far as mfa is concerned

            you_can_break_here = True

        except Exception as err:
            return dict(logged_in=False, role_name=None)

    # so we have a decoded_session_jwt - let's see if it is any good

    try:

        now = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

        if user_from_db_via_orm.is_deleted:
            user["logged_in"] = False
        else:

            if "email" in decoded_session_jwt:
                user["email"] = decoded_session_jwt["email"]

            user["logged_in"] = True

            # get the role_name from the user.role_id
            role = Role.query.filter_by(
                id=user_from_db_via_orm.role_id,
                is_deleted=False,
            ).first()

            user["role_name"] = role.name

            if "loggedOnAtSeconds" in decoded_session_jwt:
                user["seconds_remaining"] = int(
                    SESSION_EXPIRES_SECONDS
                    - (now - decoded_session_jwt["loggedOnAtSeconds"])
                )

            if "ip_address" in decoded_session_jwt:
                user["ip_address"] = decoded_session_jwt["ip_address"]

    except Exception as err:
        try:
            if err.args[0] == "Signature has expired":
                pass
            elif err.args[0] == "Signature verification failed":
                # throttle the responses
                # We need to do a throttle here that will not block the whole flask process
                app.logger.warning(
                    f"[WARNING] err was {err} - can come from corrupted jwt if it happens often then could be attack"
                )
        except:
            # throttle the responses
            # We need to do a throttle here that will not block the whole flask process
            app.logger.exception(f"[EXCEPTION] err was {err}")

    return user

def is_strong_enough(password):

    strong_enough = True

    # at least 8 characters long
    if len(password) < 8:
        strong_enough = False

    if len(password) > 64:
        strong_enough = False

    # count the occurreences of each character
    character_dictionary = {}
    for character in password:
        try:
            character_dictionary[character] = character_dictionary[character] + 1
        except:
            character_dictionary[character] = 1

    # if any character makes up more than half
    for character in character_dictionary:
        count = character_dictionary[character]
        if count / len(password) > 0.5:
            strong_enough = False

    # if there aren't at least 3 different characters
    if len(character_dictionary) < 3:
        strong_enough = False

    # check if it is in the list of bad pawords
    if password in bad_password_set:
        strong_enough = False

    letters = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
    ]

    # check it has at least one upper case character
    has_upper_case = False
    for character in password:
        if not character.lower() in letters:
            continue
        if character == character.upper():
            has_upper_case = True
            break
    if not has_upper_case:
        strong_enough = False

    # check it has at least one lower case character
    has_lower_case = False
    for character in password:
        if not character.lower() in letters:
            continue
        if character == character.lower():
            has_lower_case = True
            break
    if not has_lower_case:
        strong_enough = False

    # check it has at least one integer
    has_integer = False
    for character in password:
        try:
            character = int(character)
            has_integer = True
            break
        except:
            pass
    if not has_integer:
        strong_enough = False

    # Aa1pch5gthdfw  should pass
    # Aa1-----  should fails as too many repeats
    # Aa-acbypght-  should fails as no digit
    # aa1hlrpdvw # should fail as no uppercase
    # AG1PHDRFVSINWP # should fail as no lowercase
    # Aa1hlrp # should fail as too short aa1hlrpdvw

    return strong_enough

def send_password_reset_email(user):

    """
    There is a vulnerability with this method whereby the emailed link could be intercepted and used by a bad actor
    It can be mitigated by providing a secure token in a cookie when the user requests the reset
    Then the link clicked api can also present the same token back so we effectively have confirmation that the original machine
    that requested the reset is the same machine that is used to modify the password
    See more here: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
    todo: remove the vulnerability
    """
    expires_in_seconds = 10 * 60
    expires_in_minutes = int(expires_in_seconds / 60)
    token = user.get_token(
        token_purpose="reset_password", expires_in_seconds=expires_in_seconds
    )
    href_link = (
        url_for("api_reset_password", _external=True)[0:-1]
        + "?password_reset_token="
        + token
    )
    href_link = href_link.replace("api_reset_password", "passwordresetview")

    user_dict = user.get_dict()

    reset_password_html = """
        <p>Hello {{ user_dict["name"] }}</p>
        <strong>This link is valid for {{  expires_in_minutes }} minutes from the time of sending.</strong>
        <p>
            To reset your password for the readiness tracker - 
            <a href="{{ href_link}}">
                click here
            </a>.
        </p>
        <p>Alternatively, you can paste the following link in your browser's address bar:</p>
        <p>{{ href_link }}</p>
        <p>If you have not requested a password reset simply ignore this message.</p>
        <p>Regards</p>
        <p>The Readiness Tracker Support Team </p>    
    
    """
    reset_password_text = """
Hello {{ user_dict["name"] }},

This link is valid for {{  expires_in_minutes }} minutes from the time of sending.

To reset your password for the readiness tracker click on the following link:

{{ href_link}}

If you have not requested a password reset simply ignore this message.

Regards,

The Readiness Tracker Support Team   

    """
    did_it_send = send_email(
        "Reset Your Password for the Readiness Tracker...",
        sender=app.config["ADMINS"][0],
        recipients=[user_dict["email"]],
        text_body=render_template_string(
            reset_password_text,
            user_dict=user_dict,
            href_link=href_link,
            expires_in_seconds=expires_in_seconds,
            expires_in_minutes=expires_in_minutes,
        ),
        html_body=render_template_string(
            reset_password_html,
            user_dict=user_dict,
            href_link=href_link,
            expires_in_seconds=expires_in_seconds,
            expires_in_minutes=expires_in_minutes,
        ),
        send=True,
    )

    return

def send_email(subject, sender, recipients, text_body, html_body, send=False, cc=None):

    # never have a mutable variable as a default
    if not cc:
        cc = []

    # stop the demo emails attempting to send
    for recipient in recipients:

        if "e_1@" in recipient:
            send = False
        if "e_2@" in recipient:
            send = False
        if "e_3@" in recipient:
            send = False

    msg = Message(subject, sender=sender, recipients=recipients, cc=cc)
    msg.body = text_body
    msg.html = html_body
    # do not sentd email for the moment
    try:
        if send:
            mail.send(msg)
    except Exception as err:
        app.logger.exception(
            f"[EXCEPTION] sending email msg.sender was: {msg.sender} \nerr was {err}"
        )

    return msg

if __name__ == "__main__":
    app.run(debug=True)
def gather_and_log_response_times(route_name, time_started):

    try:
        time_taken = time.time() - time_started

        timings = route_timings[route_name]["timings"]
        timings.append(time_taken)

        if site_config["INSTANCE_TYPE"] == "development":
            critical_time = 0.5
            warning_time = 0.25
            info_time = 0.05
            debug_time = 0
        else:
            critical_time = 1
            warning_time = 0.5
            info_time = 0
            debug_time = 0

        if len(timings) >= 50:
            number_of_records = len(timings)
            average_response_time = sum(timings) / len(timings)
            route_timings[route_name] = dict(
                time_started=int(time.time()), timings=[time_taken]
            )
            if average_response_time > 1.5:
                app.logger.critical(
                    f"[TIMING] response times for {route_name} are {round(average_response_time,3)} seconds from {number_of_records} transactions"
                )
            elif average_response_time > 0.75:
                app.logger.warning(
                    f"[TIMING] response times for {route_name} are {round(average_response_time,3)} seconds from {number_of_records} transactions"
                )
            elif average_response_time > 0.01:
                app.logger.info(
                    f"[TIMING] response times for {route_name} are {round(average_response_time,3)} seconds from {number_of_records} transactions"
                )
            elif average_response_time > 0.00:
                app.logger.debug(
                    f"[TIMING] response times for {route_name} are {round(average_response_time,3)} seconds from {number_of_records} transactions"
                )

    except:

        route_timings[route_name] = dict(
            time_started=int(time.time()), timings=[time_taken]
        )

    return
