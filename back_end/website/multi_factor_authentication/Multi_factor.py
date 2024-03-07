# This module contains the class and methods required for multifactor authentication via google authenticator

import qrcode
import pyotp
import numpy as np
import cv2
import os
import time
import threading

this_directory = os.path.abspath(os.path.dirname(__file__))


class Multi_factor:
    def __init__(self, url=None, number_to_prepare=100):
        self.url = url

    # method called when creating a unique qr for a user logging in without recorded MFA credentials
    def get_secret_and_image(self, email, secret=None, timing_array=None):

        time_started = time.time()
        if not secret:
            secret = pyotp.random_base32()
        token_for_image_creator = pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.url, issuer_name=f"Scaffolding - {email}"
        )
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(token_for_image_creator)
        qr.make(fit=True)

        qr_code_image = []

        qr_code_image = qr.make_image(fill_color="black", back_color="white")

        qr_code_image = np.array(qr_code_image.getdata()).reshape(qr_code_image.size[0], qr_code_image.size[1])

        if type(timing_array) == type([]):
            timing_array.append(time.time()-time_started)

        return secret, qr_code_image

    # takes the secret from the user and gets the current otp to compare with the user provided one
    def get_current_otp(self,secret):
        totp = pyotp.TOTP(secret)
        current_otp = totp.now()

        return current_otp  

def wait_for_threads_to_complete(threads):

    all_finished = False
    while not all_finished:
        all_finished = True
        for thread in threads:
            alive = thread.is_alive()
            if alive:
                all_finished = False
                time.sleep(0.1)
                # break back to the while
                break
            pass
    return


if __name__ == "__main__":

    try:
        path_to_output = os.path.join(this_directory, "output_no_git")
        os.mkdir(path_to_output)
    except:
        pass

    # Create the object that will get the stuff 
    multi_factor = Multi_factor(url="http://127.0.0.1:5000/")

    secret, image = multi_factor.get_secret_and_image("luke.davey@dt-squad.com",secret="S4TEWGAZNE5TBJ4KU3YQT3CJJE2E7ZAB")
    path_to_image = os.path.join(path_to_output, "authenticator.png")
    cv2.imwrite(path_to_image, image)   


    global_threads = []
    timing_array = []

    concurrent_users = 300
    elapsed_time = 20

    for __ in range(concurrent_users):

        threaded_function = multi_factor.get_secret_and_image
        kwargs = dict(timing_array=timing_array)
        args = ["pbs@dt-squad.com"]
        thread = threading.Thread(target=threaded_function, args=args, kwargs=kwargs)
        global_threads.append(thread)
        thread.start()

        # handle the elapsed time
        sleep_time = elapsed_time / concurrent_users
        time.sleep(sleep_time)

    wait_for_threads_to_complete(global_threads)

    average_response_time = sum(timing_array) / len(timing_array)


    secret, image = multi_factor.get_secret_and_image("pbs@dt-squad.com")
    path_to_image = os.path.join(path_to_output, "authenticator.png")
    cv2.imwrite(path_to_image, image)   

    current_otp = multi_factor.get_current_otp(secret)
    print("Current OTP:", current_otp)
    while True:
        if current_otp == multi_factor.get_current_otp(secret):
            time.sleep(0.01)
            continue
        current_otp = multi_factor.get_current_otp(secret)
        print(f"For secret: {secret}, Current OTP: {current_otp}", )


    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

    url = "www.readiness-tracker.co.uk"
    qr.add_data(url)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")

    qr_code_image = np.array(image.getdata()).reshape(image.size[0], image.size[1])

    path_to_image = os.path.join(path_to_output, "test.png")
    cv2.imwrite(path_to_image, qr_code_image)

    secret_key = pyotp.random_base32()

    something = pyotp.totp.TOTP("JBSWY3DPEHPK3PXP").provisioning_uri(
        name=url, issuer_name="Secure App"
    )

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(something)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")

    qr_code_image = np.array(image.getdata()).reshape(image.size[0], image.size[1])

    path_to_image = os.path.join(path_to_output, "authenticator.png")
    cv2.imwrite(path_to_image, qr_code_image)

    # now we should be able to get the otp from the authenticator app and validate it here
    # authenticator_code = input("code please: ")

    totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
    current_otp = totp.now()
    print("Current OTP:", totp.now())
    while True:
        if current_otp == totp.now():
            time.sleep(0.01)
            continue
        current_otp = totp.now()
        print("Current OTP:", current_otp)

    1 / 0
