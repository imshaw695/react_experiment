# As a one off when the app is first created:
# type: python -m  flask db init and cd back_end

# When you make updates to the models in this file, you need to bring the database into synch with it
# open a terminal with the correct environment activated
# type: python -m flask db migrate -m "Initial migration."
# 
# Then check the sql update statements in the script that was generated. 
# NB This is an important check, not a cursory glance!
# NB They might be wrong!
# 
# When you are confident they are correct, 
# type: python -m flask db upgrade
# 
# The database is now updated to reflect this model file
# 

import os
import jwt
from datetime import datetime, timedelta
from flask import current_app as app
from website import db, site_config

import time
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func, expression, and_, or_
from website.pii_data_handlers import get_data_from_encrypted_data, get_encrypted_data, get_encryption_key_from_encryption_key_as_string, get_encryption_keys_from_dot_env, get_latest_encryption_key_and_id

ENCRYPTION_KEYS = get_encryption_keys_from_dot_env()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", name = "fk_users_roles", ondelete="CASCADE"),nullable=False)
    name = db.Column(db.String(200), unique=False, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    failed_login_streak = db.Column(db.Integer, server_default="0")
    hashed_password = db.Column(db.String(128), unique=False, nullable=False)
    mfa_secret = db.Column(db.String(100), unique=False, nullable=True)
    mfa_secret_confirmed = db.Column(db.BOOLEAN, nullable=False, server_default=expression.false())
    is_deleted = db.Column(db.BOOLEAN, nullable=False, server_default=expression.false())
    created_timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    pii_key_id = db.Column(db.Integer, index=True, nullable=False, server_default="0")

    def get_user_by_email(email):  

        encryption_key_indices = list(ENCRYPTION_KEYS.keys())
        encryption_key_indices = reversed( encryption_key_indices)

        for encryption_key_index in encryption_key_indices:
            ENCRYPTION_KEY = ENCRYPTION_KEYS[encryption_key_index]
            encrypted_email = get_encrypted_data(email, ENCRYPTION_KEY)

            user = User.query.filter_by(
                email=encrypted_email,
                is_deleted=False,
            ).first()

            if user:
                if user.pii_key_id == encryption_key_index:
                    return user

        return None

    def is_user_authorised(user, crud_operation, new_values_dictionary=None):

        if crud_operation in ["create","update"]:
            if not new_values_dictionary:
                return False
                
            # must make sure no role_name elevation is being attempted
            # get the role_level
            # get the editors record 

            edited = User.query.filter_by(id=new_values_dictionary["id"]).first()
            
            editor = User.get_user_by_email(user["email"])

            editors_role = Role.query.filter_by(name=user["role_name"]).first()

            # If I get to here then they are editing themselves with no role change or 
            # editing a user with a lower level than them        

            # some specific checks if it is an update
            if crud_operation == "update":

                if not edited:
                    app.logger.critical(
                    f"[ACCESS] The user {user} tried to alter a user with no valid id: ({new_values_dictionary})")
                    return False                     

                # get the role record of existing edited user or new role_id if trying to change role_id
                role_changed = False
                if "role_id" in new_values_dictionary:
                    edited_role = Role.query.filter_by(id=new_values_dictionary["role_id"]).first()
                    if not edited.role_id == edited_role.id:
                        role_changed = True   
                else:
                    edited_role = Role.query.filter_by(id=edited.role_id).first() 

                # is the editor the same person as the user
                ok = True
                editing_self = False
                if editor.email == edited.email:
                    editing_self = True
                    if role_changed:
                        ok = False
                else:
                    # I can only edit people whose level is lower than mine
                    # and if the role level has changed, that new level must also be lower than mine 
                    # as edited_role.level is calculated correctly, this one test is enough
                    if not edited_role.level < editors_role.level:
                        ok =False

                # users can edit themselves 
                if editing_self:
                    # ok is True or False depending
                    return ok                             
            
            else:
                # it is a create 
                # the role_id in the new_values_dictionary must be less than the role_id of the editor
                # get the level of the new one 
                created_role = Role.query.filter_by(id=new_values_dictionary["role_id"]).first()
                if created_role.level < editors_role.level:
                    ok = True
                else:
                    ok=False

            # level breach is attempted 
            if not ok:
                app.logger.critical(
                f"[ACCESS] The user {user} tried to elevate this users role inappropriately: ({new_values_dictionary})"
            )
                return False

        # the levels / role names are ok - check the user is allowed
        crud_authorities = dict(
            create= ["super user", "ho user",],
            read = ["ho user", "super user"],
            update= ["super user", "ho user",],
            delete = ["super user", "ho user",]
        )
        if user["role_name"] in crud_authorities[crud_operation]:
            authorised = True
        else:
            authorised = False
            app.logger.critical(
            f"[ACCESS] The user {user} tried to add another but they are not authorised: ({new_values_dictionary})"
        )
        return authorised

    def get_dict(self):
        # decrypt pii

        try:
            name = get_data_from_encrypted_data(self.name, ENCRYPTION_KEYS[self.pii_key_id])
        except:
            name = "not known"

        try:
            email = get_data_from_encrypted_data(self.email, ENCRYPTION_KEYS[self.pii_key_id]).lower()
        except:
            email = "not known"

        # try:
        #     cc_emails = get_data_from_encrypted_data(self.cc_emails, ENCRYPTION_KEYS[self.pii_key_id])
        # except:
        #     cc_emails = "not known"

        try:
            mfa_secret = get_data_from_encrypted_data(self.mfa_secret, ENCRYPTION_KEYS[self.pii_key_id])
        except:
            mfa_secret = ""

        return_package = dict(id=self.id, role_id=self.role_id, created_timestamp=self.created_timestamp, name=name, email=email, is_deleted=self.is_deleted, failed_login_streak=self.failed_login_streak, pii_key_id=self.pii_key_id, mfa_secret = mfa_secret, mfa_secret_confirmed=self.mfa_secret_confirmed)

        return  return_package

    def update_from_dictionary(instance, dictionary):
        # get the latest encryption key 
        latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)

        return_package = dict(message="Update applied", rc=0)
        try:
            if "role_id" in dictionary:
                instance.role_id = dictionary["role_id"]

            # tricked by this once so adding more detailed explanation
            # we are updating the user from a dictionary
            # The name, email and cc_amails may or may not be being updated themselves 
            # If they are being updated we can simply encrypt the data with the latest encryption key and then store the enncrypted data 
            # If they are not being updated then we must ensure that we are using the latest encryption key... 
            # so need to unencrypt the data on the record with the key id stored on the instance, then encrypt it with the latest encryption key
            # then finally store the latest encryption key id on the record
            if "name" in dictionary:
                instance.name = get_encrypted_data(dictionary["name"], latest_encryption_key) 
            else:
                name = get_data_from_encrypted_data(instance.name, ENCRYPTION_KEYS[instance.pii_key_id]) 
                instance.name = get_encrypted_data(name, latest_encryption_key) 

            if "email" in dictionary:
                instance.email = get_encrypted_data(dictionary["email"].lower(), latest_encryption_key) 
            else:
                email = get_data_from_encrypted_data(instance.email, ENCRYPTION_KEYS[instance.pii_key_id]) 
                instance.email = get_encrypted_data(email.lower(), latest_encryption_key) 

            # if "cc_emails" in dictionary:
            #     instance.cc_emails = get_encrypted_data(dictionary["cc_emails"], latest_encryption_key) 
            # else:
            #     if not instance.pii_key_id:
            #         instance.pii_key_id = pii_key_id
            #     cc_emails = get_data_from_encrypted_data(instance.cc_emails, ENCRYPTION_KEYS[instance.pii_key_id]) 
            #     instance.cc_emails = get_encrypted_data(cc_emails, latest_encryption_key) 

            instance.pii_key_id = pii_key_id

            if "hashed_password" in dictionary:
                instance.hashed_password = dictionary["hashed_password"]

            if "failed_login_streak" in dictionary:
                instance.failed_login_streak = dictionary["failed_login_streak"]

            if "mfa_secret_confirmed" in dictionary:
                instance.mfa_secret_confirmed = dictionary["mfa_secret_confirmed"]

            if "mfa_secret" in dictionary:
                instance.mfa_secret = get_encrypted_data(dictionary["mfa_secret"], latest_encryption_key) 
            else:
                if not instance.pii_key_id:
                    instance.pii_key_id = pii_key_id
                mfa_secret = get_data_from_encrypted_data(instance.mfa_secret, ENCRYPTION_KEYS[instance.pii_key_id]) 
                instance.mfa_secret = get_encrypted_data(mfa_secret, latest_encryption_key)                 

        except Exception as err: 
            return_package = dict(message=f"Update not applied: {err}", rc=4)

        return return_package   

    def get_token(self, expires_in_seconds=600, token_purpose="general"):
        return jwt.encode(
            {token_purpose: self.id, 'exp': time.time() + expires_in_seconds},
            app.config['SECRET_KEY'], algorithm='HS512') 

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)   

    def update_to_latest_pii_key(self):

        user_data = self.get_dict()

        latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)

        if not user_data["pii_key_id"] == pii_key_id:
            user_data["pii_key_id"] = pii_key_id
            # we're going to re_encrypt
            User.update_from_dictionary(self, user_data)
            try:
                db.session.commit()
            except Exception as err:
                app.logger.exception(f"[EXCEPTION] err was {err}")
                app.logger.critical(
            f"[DATA INTEGRITY] When trying to update a users pii_key, a failure occurred. the user_id was {user_data['id']}. Check that a duplicate has not crept in"
        )
                db.session.rollback()
                db.session.flush()

            user_data_post_update = self.get_dict()
            
            you_can_break_here = True

        return

    @staticmethod
    def update_all_to_latest_pii_key():
        '''
            This function will 
        '''
        time_started = time.time()

        latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)

        # get list of user that are not on the latest key 
        users = []
        err = ""
        try:
            users = User.query.filter(User.pii_key_id != pii_key_id).all()

        except Exception as err:
            you_can_break_here = True

        for user in users:
            
            user.update_to_latest_pii_key()

            you_can_break_here = True

        log_message = f"[TIMING] Just updated the pii key for {len(users)} users. It took {round(time.time() - time_started,3)} seconds"
        if len(users)>0:
            app.logger.info(log_message)
            
        return                

    @staticmethod
    def verify_token(token, token_purpose="general"):
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS512'])[token_purpose]
        except:
            decoded_token = None
        return decoded_token                   

# different roles are associated with different priveledges, or access rights, to make read, write,
# or delete data
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    level = db.Column(db.Integer, default=0, nullable=False)
    is_deleted = db.Column(db.BOOLEAN, nullable=False, server_default=expression.false())
    created_timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def is_user_authorised(user, crud_operation):
        crud_authorities = dict(
            create= ["super user"],
            read = ["user", "ho user", "super user"],
            update= ["super user"],
            delete = ["super user"]
        )
        if user["role_name"] in crud_authorities[crud_operation]:
            authorised = True
        else:
            authorised = False
        return authorised

    def get_dict(self):
        return dict(id=self.id,  created_timestamp=self.created_timestamp, name=self.name, level=self.level, is_deleted=self.is_deleted) 

    def __repr__(self):
        return dict(id=self.id, name=self.name) 

    def update_from_dictionary(instance, dictionary):

        return_package = dict(message="Update applied", rc=0)
        try:
            instance.name = dictionary["name"]
        except Exception as err:
            return_package = dict(message=f"Update not applied: {err}", rc=4)
        try:
            instance.level = dictionary["level"]
        except Exception as err:
            return_package = dict(message=f"Update not applied: {err}", rc=4)

        return return_package    

class Log(db.Model):
    #
    # Inspired by stack overflow: 
    # https://stackoverflow.com/questions/52728928/setting-up-a-database-handler-for-flask-logger
    #
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True) # auto incrementing
    logger = db.Column(db.String(100)) # the name of the logger. (e.g. myapp.views)
    level = db.Column(db.String(100), index=True) # info, debug, or error?
    trace = db.Column(db.String(4096)) # the full traceback printout
    msg = db.Column(db.String(4096)) # any custom log you may have included
    # support_email_sent = db.Column(db.DateTime, index=True)
    created_timestamp = db.Column(db.DateTime, index=True, default=db.func.now()) # the current timestamp
    pii_key_id = db.Column(db.Integer, index=True, nullable=False, server_default="0")


    def is_user_authorised(user, crud_operation):
        crud_authorities = dict(
            create= [""],
            read = ["support", "super user"],
            update= [],
            delete = []
        )
        if user["role_name"] in crud_authorities[crud_operation]:
            authorised = True
        else:
            authorised = False
        return authorised

    def get_dict(self):
        try:
            if self.trace.find("NoneType") > -1:
                trace = ""
            else:
                trace =  self.trace
        except:
            trace = ""

        if self.level == "CRUD":
            try:
                msg = get_data_from_encrypted_data(self.msg, ENCRYPTION_KEYS[self.pii_key_id])
                msg = "able to decrypt"
            except:
                msg = "unable to decrypt"

        # try:
        #     support_email_sent = self.support_email_sent.strftime('%m/%d/%Y-%H:%M:%S')
        # except:
        #     support_email_sent = ""
        dictionary = dict(id=self.id,  created_timestamp=self.created_timestamp.strftime('%m/%d/%Y-%H:%M:%S'), logger=self.logger, level=self.level, trace=trace, msg=self.msg ) 

        return dictionary

    def __init__(self, logger=None, level=None, trace=None, msg=None):

        if level == "CRUD":
            latest_encryption_key, pii_key_id = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)
            msg = get_encrypted_data(msg, latest_encryption_key)
            self.pii_key_id = pii_key_id
        self.logger = logger
        self.level = level
        self.trace = trace
        self.msg = msg

    def get_dict(self):
        # decrypt pii
        if self.level == "CRUD":
            try:
                msg = get_data_from_encrypted_data(self.msg, ENCRYPTION_KEYS[self.pii_key_id])
            except:
                msg = "not known"
        else:
            msg = self.msg

        return_package = dict(logger=self.logger, level=self.level, trace=self.trace, msg=msg)

        return  return_package        

    def __unicode__(self):
        return self.__repr__()

    def __repr__(self):
        return f"<Log: {self.created_timestamp.strftime('%m/%d/%Y-%H:%M:%S')} - {self.level} - {self.msg[:50]}>"    

    def delete_old_logs():

        log_levels = []
        if site_config["INSTANCE_TYPE"] == "development":
            log_levels.append(dict(level="DEBUG", max_age_in_days=0.5))
            log_levels.append(dict(level="INFO", max_age_in_days=0.5))
            log_levels.append(dict(level="WARNING", max_age_in_days=0.5))
            log_levels.append(dict(level="ERROR", max_age_in_days=0.5)) 
            log_levels.append(dict(level="CRITICAL", max_age_in_days=0.5))
            log_levels.append(dict(level="CRUD", max_age_in_days=0.5))
        else:
            log_levels.append(dict(level="DEBUG", max_age_in_days=0.5))
            log_levels.append(dict(level="INFO", max_age_in_days=3))
            log_levels.append(dict(level="WARNING", max_age_in_days=31*13))
            log_levels.append(dict(level="ERROR", max_age_in_days=31*13)) # until deleted manually as fixed
            log_levels.append(dict(level="CRITICAL", max_age_in_days=31*13))
            log_levels.append(dict(level="CRUD", max_age_in_days=31*13))

        now = time.time()   
        test = time.strftime('%Y-%m-%d %H:%M:%S')

        current_dateTime = datetime.now()

        #  date_1 = datetime.strptime(test, "%m/%d/%y")

        end_date = current_dateTime + timedelta(days=-10)
        test_2 = end_date.strftime('%Y-%m-%d %H:%M:%S')

        count = 0

        for log_level in log_levels:

            this_date = current_dateTime + timedelta(days=-log_level['max_age_in_days'])
            
            logs_to_delete = Log.query.filter(and_(Log.level==log_level['level']),(Log.created_timestamp<this_date) )
            count_deleted = logs_to_delete.count()
            count = count + count_deleted
            logs_to_delete.delete()
            db.session.commit()
            break_here = True

        # now delete the test exception logs  
        this_date = current_dateTime + timedelta(days=-0.1)      
        logs_to_delete = Log.query.filter(and_(Log.msg=="[INITIALISING] Testing that a exception log comes out as we are in development environment"),(Log.created_timestamp<this_date) )
        count_deleted = logs_to_delete.count()
        count = count + count_deleted
        logs_to_delete.delete()
        db.session.commit()
        break_here = True
        return count

    # def get_logs_needing_emails():

    #     logs_needing_emails = Log.query.filter(and_(Log.support_email_sent.is_(None), (or_((Log.level=="ERROR"),(Log.level=="CRITICAL")))) )

    #     return logs_needing_emails

    # def update_email_sent(self):

    #     self.support_email_sent = db.func.now()
    #     db.session.commit()

    #     return


    def update_to_latest_pii_key(self):

        log_data = self.get_dict()

        latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)

        if log_data["level"] == "CRUD":
            if not self.pii_key_id == pii_key_id:
                # we're going to re_encrypt
                self.pii_key_id = pii_key_id
                self.msg = get_encrypted_data(log_data["msg"],latest_encryption_key)
                try:
                    db.session.commit()
                except Exception as err:
                    db.session.rollback()
                    db.session.flush()

        return

    @staticmethod
    def update_all_to_latest_pii_key():
        '''
            This function will 
        '''
        time_started = time.time()
        latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)
        # get list of logs that are not on the latest key 
        logs = []
        err = ""
        try:
            logs = Log.query.filter(and_(Log.level=="CRUD"),(Log.pii_key_id != pii_key_id) ).all()
        except Exception as err:
            you_can_break_here = True

        for log in logs:
            
            log.update_to_latest_pii_key()

            you_can_break_here = True

        log_message = f"[TIMING] Just updated the pii key for {len(logs)} logs. It took {round(time.time() - time_started,3)} seconds"
        if len(logs)>0:
            app.logger.info(log_message)
            
        return              
