import hashlib
import os
import binascii


class Role:
    def __init__(self, name, permissions):
        self.name = name
        self.permissions = permissions


# Define roles and associated permissions
roles = {
    "Doctor": Role("Doctor", ["read_record", "add_record", "update_record"]),
    "Nurse": Role("Nurse", ["read_record"]),
    "Administrator": Role( "Administrator",["read_record", "add_record", "update_record", "mine_block", "update_user"]),
    "Patient": Role("Patient", ["grant_consent", "revoke_consent", "read_own_record"]),
}


# The class responsible for storing and authenticating users
class User:
    def __init__(self, username, password, role_name, public_key, skip_hash=False):
        self.username = username
        self.password = password if skip_hash else self.hash_password(password)
        self.role_name = role_name
        self.public_key = public_key

    # The method for hashing the passwords for storing
    @staticmethod
    def hash_password(password):
        # Hashing a password for storing
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii")
        pwdhash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode("ascii")

    # Method for validating the passwords inputted by the user and comparing them to the stored password
    @staticmethod
    def validate_password(input_password, stored_password):
        salt = stored_password[:64]
        stored_hash = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac(
            "sha512", input_password.encode("utf-8"), salt.encode("ascii"), 100000
        )
        pwdhash = binascii.hexlify(pwdhash).decode("ascii")
        return pwdhash == stored_hash
