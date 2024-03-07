import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from dotenv import load_dotenv

'''
    All the routines for managing the encryption and decryption of pii data 

    Also allows for automatically updating the pii key and re-encrypting the data 

    In the models.py file there is a function in the User class 
        update_all_to_latest_pii_key()

'''

def b64e(string):
    # takes a string of data 
    # returns a string representation of b64 encoded data
    x = base64.b64encode(string.encode()).decode()
    return x

def b64d(string):
    # takes a string representation of b64 encoded data 
    # returns a string of the original data 
    x = base64.b64decode(string).decode()
    return x

def get_encrypted_data(data_as_string, ENCRYPTION_KEY):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_SIV)
    data_as_string = data_as_string.encode(encoding='utf-8')

    ciphertext, tag = cipher.encrypt_and_digest(data_as_string)  

    tag_as_string = base64.b64encode(tag, altchars=None).decode(encoding='utf-8')
    ciphertext_as_string = base64.b64encode(ciphertext, altchars=None).decode(encoding='utf-8')

    encrypted_data = f"{len(tag_as_string) + 1} {tag_as_string} {ciphertext_as_string}"

    return encrypted_data

def get_data_from_encrypted_data(encrypted_data, ENCRYPTION_KEY):

    if encrypted_data:

        first_space_index = encrypted_data.find(" ")
        length_of_tag = int(encrypted_data[0:first_space_index])

        tag_starts_at = first_space_index + 1
        tag_as_string = encrypted_data[tag_starts_at:tag_starts_at+length_of_tag-1]
        cipher_as_string = encrypted_data[tag_starts_at+length_of_tag:]

        tag = base64.b64decode(tag_as_string)
        ciphertext = base64.b64decode(cipher_as_string)

        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_SIV)
        try:
            data_as_string = cipher.decrypt_and_verify(ciphertext, tag).decode(encoding='utf-8')
        except Exception as err:
            you_can_break_here = True
    
    else:
        data_as_string = ""


    return data_as_string

def get_suitable_encryption_key():
    encryption_key_as_bytes = get_random_bytes(64)
    encryption_key_as_string =  base64.b64encode(encryption_key_as_bytes, altchars=None).decode(encoding='utf-8')

    return encryption_key_as_string

def get_encryption_key_from_encryption_key_as_string(encryption_key_as_string):

    ENCRYPTION_KEY = base64.b64decode(encryption_key_as_string)

    return ENCRYPTION_KEY

def get_encryption_keys_from_dot_env():

    ENCRYPTION_KEYS = {}

    maximum_key_index = 999999

    for key_index in range(maximum_key_index):

        ENCRYPTION_KEY_AS_STRING = os.environ.get(f"ENCRYPTION_KEY_AS_STRING_{key_index}")
        if ENCRYPTION_KEY_AS_STRING:
            ENCRYPTION_KEY = get_encryption_key_from_encryption_key_as_string(ENCRYPTION_KEY_AS_STRING)
            ENCRYPTION_KEYS[key_index] = ENCRYPTION_KEY
        else:
            # If I already have some encryption keys then I am at the end of the available ones 
            # allow the keys to not start at zero
            pass
            if len(ENCRYPTION_KEYS) > 0:
                break
    
    return ENCRYPTION_KEYS

def test_get_encryption_keys_from_dot_env():

    this_directory = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(os.path.join(this_directory,"..", '.env'),override=True)

    ENCRYPTION_KEYS = get_encryption_keys_from_dot_env()

    # now use each of the encryption keys to encrypt then decrypt a message 
    ok = True
    for encryption_key_index   in ENCRYPTION_KEYS:
        ENCRYPTION_KEY = ENCRYPTION_KEYS[encryption_key_index]
        data_as_string = "pbs@dt-squad.com"

        try:
            encrypted_data =get_encrypted_data(data_as_string, ENCRYPTION_KEY)
            email_returned = get_data_from_encrypted_data(encrypted_data, ENCRYPTION_KEY)  
        except:
            email_returned = ""
            ok= False
            pass

        if data_as_string == email_returned:
            print(f"[SUCCESS] Get and use ENCRYPTED_KEYS_{encryption_key_index} - Test worked ")  
        else:
            ok = False
            print(f"[FAILURE] Get and use ENCRYPTED_KEYS_{encryption_key_index} - Test failed")  

    return ok

def test_get_suitable_encryption_key():
    

    encryption_key_as_string = get_suitable_encryption_key()
    ENCRYPTION_KEY = get_encryption_key_from_encryption_key_as_string(encryption_key_as_string)

    data_as_string = "pbs@dt-squad.com"
    encrypted_data =get_encrypted_data(data_as_string, ENCRYPTION_KEY)
    email_returned = get_data_from_encrypted_data(encrypted_data, ENCRYPTION_KEY)  

    ok = True

    if data_as_string == email_returned:
        print("[SUCCESS] get a suitable encryption key - Test 1 worked ")  
    else:
        ok = False
        print("[FAILURE] get a suitable encryption key - Test 1 failed")
    
    return ok

def get_latest_encryption_key_and_id(encryption_keys):

    sorted_encryption_key_indices = list(encryption_keys.keys())
    sorted_encryption_key_indices.sort()
    pii_key_id = sorted_encryption_key_indices[-1]
    latest_encryption_key = encryption_keys[pii_key_id] 
    
    return latest_encryption_key, pii_key_id 

def get_instructions():

    encryption_keys_from_dot_env = get_encryption_keys_from_dot_env()

    instructions = f'''
    WARNING
    
    The SECRET_KEY is used for certain hashing functions inside Flask 
    It can create a slight inconvenience if changed when users are signed on
    But generally, it is safe to replace the key on a regular basis or if you believe it has
    been compromised.
    The following key has been generated just now as an example of a very good and secure key 
    The format is correct for placing in the .env file 
    SECRET_KEY = {get_suitable_encryption_key()}

    The ENCRYPTION_KEY_AS_STRING_n keys are much more dangerous and MUST not be changed 
    When we add a new key on the end with the next sequential number, it will be used to 
    re-encrypt the pii data on every user record

    You must not remove any earlier keys unless you are 100% certain that there are no 
    remaining records that use the key

    If these keys are lost, the data cannot be unencrypted 

    The keys are extremely important 

    Secure them according to our latest standards

    The following line is the correct format to add to the .env file 
    It must be the next sequential number

    ENCRYPTION_KEY_AS_STRING_{len(encryption_keys_from_dot_env)} = {get_suitable_encryption_key()}

    SECRET_KEY = {get_suitable_encryption_key()}

    super_user_password = {get_suitable_encryption_key()[0:30]}

    support_user_password = {get_suitable_encryption_key()[0:30]}

    database_password = {get_suitable_encryption_key()[0:30]}

    other_password_or_secret  = {get_suitable_encryption_key()[0:30]}

    other_password_or_secret  = {get_suitable_encryption_key()[0:30]}

    other_password_or_secret  = {get_suitable_encryption_key()[0:30]}

    Use caution and follow procedures before you replace the values in the .env

    The nature of .env means that it is not copied or secured in any way

    '''

    return instructions

if __name__ == "__main__":
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

    '''
        During discussion with Paul Cuttriss, he observed that MODE_EAX may be preferrable to MODE_SIV 
        He does not proclaim to be an expert in cryptography but 
        EAX was designed for NIST 
        It's not easy to find much more information about MODE_SIV that is not in the pycryptodome site
        todo: research further to decide if we need to change
    '''
    this_directory = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(os.path.join(this_directory,"..", '.env'),override=True)

    ENCRYPTION_KEYS = get_encryption_keys_from_dot_env()
    latest_encryption_key, pii_key_id  = get_latest_encryption_key_and_id(ENCRYPTION_KEYS)
    test_get_encryption_keys_from_dot_env()
    test_get_suitable_encryption_key()

    print(get_instructions())


