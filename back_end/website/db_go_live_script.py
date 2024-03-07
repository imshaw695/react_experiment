# Running this script will populate the db with super users needed to start creating other users

import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
import secrets

this_directory = os.path.abspath(os.path.dirname(__file__))

load_dotenv(os.path.join(this_directory,"..", '.env'),override=True)

from utilities import get_sql, get_db_connection

try:
    from website.pii_data_handlers import  get_encrypted_data,  get_encryption_keys_from_dot_env, get_latest_encryption_key_and_id
except:
    from pii_data_handlers import  get_encrypted_data,  get_encryption_keys_from_dot_env, get_latest_encryption_key_and_id

try:
    from website.utilities import get_db_connection
except:
    from utilities import get_db_connection

# This script is always running locally 
# we should always use the latest encryption key to stop attempts to create duplicate users 
ENCRYPTION_KEYS = get_encryption_keys_from_dot_env()
latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)

def create_system_users():

    load_dotenv(os.path.join(this_directory, "..", ".env"), override=True)

    super_user_name = os.environ.get("super_user_name")
    super_user_email = os.environ.get("super_user_email")
    super_user_password = os.environ.get("super_user_password")
    create_user(
        super_user_name,
        super_user_email,
        super_user_password,
        "super user",
    )

    support_user_name = os.environ.get("support_user_name")
    support_user_email = os.environ.get("support_user_email")
    support_user_password = os.environ.get("support_user_password")
    create_user(
        support_user_name,
        support_user_email,
        support_user_password,
        "support",
    )

    return


def create_user(
    name,
    email,
    password,
    role_name,
):

    # We are now storing pii data after encryption
    name = get_encrypted_data(name, latest_encryption_key)
    email = get_encrypted_data(email, latest_encryption_key)

    hashed_password = generate_password_hash(password)

    roles = get_records_by_name("roles", role_name)
    role_id = roles[0]["id"]

    users = get_records_by_name("users", name)
    users = get_records_by_field_value("users", "email", email)
    for user in users:
        if user["email"] == email:
            sql = f"""DELETE FROM users WHERE email = '{email}';"""
            sql = sql.replace("\n", "")
            with get_db_connection() as db_connection:
                cursor = db_connection.cursor()
                test = cursor.execute(sql)
                test2 = db_connection.commit()

    sql = f"""
        INSERT INTO users (role_id,  name, email, hashed_password, pii_key_id)
        VALUES ({role_id}, '{name}', '{email}', '{hashed_password}', '{pii_key_id}' );    
    """

    sql = sql.replace("\n", "")

    with get_db_connection() as db_connection:
        cursor = db_connection.cursor()
        test = cursor.execute(sql)
        db_connection.commit()

    return


def get_records(table):

    with get_db_connection() as db_connection:
        cursor = db_connection.cursor()
        cursor.execute(f"SELECT * FROM {table}")

        columns = cursor.description
        # hocus pocus alert!!!
        result = [
            {columns[index][0]: column for index, column in enumerate(value)}
            for value in cursor.fetchall()
        ]

        return result

def get_records_by_name(table, name):

    with get_db_connection() as db_connection:
        cursor = db_connection.cursor()
        cursor.execute(f"SELECT * FROM {table} where name = '{name}'")

        columns = cursor.description
        # hocus pocus alert!!!
        result = [
            {columns[index][0]: column for index, column in enumerate(value)}
            for value in cursor.fetchall()
        ]

        return result


def get_records_by_field_value(table, field, value):

    with get_db_connection() as db_connection:
        cursor = db_connection.cursor()
        cursor.execute(f"SELECT * FROM {table} where {field} = '{value}'")

        columns = cursor.description

        result = []
        for value in cursor.fetchall():
            row = {}
            for index, column in enumerate(value):
                row[columns[index][0]] = column
            result.append(row)
        
        return result


def create_demo_users():
    """
    user
    ho user
    super user
    """

    users = []
    users.append(
        dict(
            password=secrets.token_urlsafe(20),
            name="Luke Davey",
            email="luke.davey@dt-squad.com",
            role_name="ho user",
        )
    )
    users.append(
        dict(
            password=secrets.token_urlsafe(20),
            name="Luke Davey",
            email="luke@thebigteam.co.uk",
            role_name="ho user",
        )
    )
    users.append(
        dict(
            password=secrets.token_urlsafe(20),
            name="Anna McGhee",
            email="anna@thebigteam.co.uk",
            role_name="ho user",
        )
    )
    users.append(
        dict(
            password=secrets.token_urlsafe(20),
            name="Simon Knocker",
            email="simon@thebigteam.co.uk",
            role_name="ho user",
        )
    )
    

    for user in users:

        create_user(
            user["name"],
            user["email"],
            user["password"],
            user["role_name"],
        )

def create_role(role_package):

    sql = f"""
        INSERT INTO roles ( name, level)
        VALUES ('{role_package['name']}','{role_package['level']}');    
    """

    sql = sql.replace("\n", "")

    with get_db_connection() as db_connection:
        cursor = db_connection.cursor()
        try:
            test = cursor.execute(sql)
            db_connection.commit()
        except:
            pass

    return


def create_roles():

    create_role(dict(name="user", level=10))
    create_role(dict(name="ho user", level=20))
    create_role(dict(name="super user", level=100))
    create_role(dict(name="support", level=15))


if __name__ == "__main__":
    
    # This must be run on the host machine as it does a local connection and uses the secrets to allow correct encryption

    create_roles()

    create_system_users()

    # Add any demo users that we want (Luke at least)
    
    # create_demo_users()

    message = '''
    The base user records have been created with some roles, views refreshed, system_users and demo_users created 

    If you want the full set of demo records, you must also run:

    back_end\create_demo_records_in_db.py

    '''
    print(message)
