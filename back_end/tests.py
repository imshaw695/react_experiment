# This module contains tests for the API's
# It is good practice to create the test, then write the API until it succeeds (TDD)

from flask import request, jsonify
import requests
from flask import current_app as app

# This API will fetch the records in the users table in json.
def api_get_records_db(table_name, port=5000):
    payload = {}
    payload["table_name"] = table_name

    # now prepare the headers, email and password for the post
    headers = {"User-Agent": "Mozilla/5.0"}

    url = f"/api_get_records_db"
    try:
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            print("status code 200")
            response_as_json = response.json()
        else:
            response_as_json = {}

    except Exception as err:
        response_as_json = {}



    return response_as_json

# This test will use 'requests' to send a POST request to the add user API with the required fields.
def test_add_user(port=5000):
    payload = {}
    payload["first_name"] = "Test"
    payload["last_name"] = "User"
    payload["address"] = "Test Address"

    # now prepare the headers, email and password for the post
    headers = {"User-Agent": "Mozilla/5.0"}

    url = f"/api_add_user"
    try:
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            print("status code 200")
            response_as_json = response.json()
        else:
            response_as_json = {}

    except Exception as err:
        response_as_json = {}

    return response_as_json



print(api_get_records_db(table_name="users"))
print(test_add_user())