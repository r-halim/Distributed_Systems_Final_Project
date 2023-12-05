from ecdsa import SigningKey, VerifyingKey, SECP256k1
import requests
import json
import hashlib
import os
import time


class BlockchainTester:
    def __init__(self, base_url):
        self.ensure_directory_exists()
        self.base_url = base_url

    # Method which makes the 'testcredentials' folder. Its used to allow the credentials to be pulled and used for the various test cases)
    def ensure_directory_exists(self):
        if not os.path.exists("testcredentials"):
            os.makedirs("testcredentials")

    # Helper method for signing up the user; used to contact the flask endpoint/pass the data to it
    def signup_user(self, username, password, role):
        user_data = self.load_user_data(username)
        if user_data:
            print(f"User {username} already exists. Loading existing keys.")
            private_key = SigningKey.from_string(
                bytes.fromhex(user_data["private_key"]), curve=SECP256k1
            )
            public_key = VerifyingKey.from_string(
                bytes.fromhex(user_data["public_key"]), curve=SECP256k1
            )
        else:
            print(f"User {username} does not exist. Generating new keys.")
            private_key = SigningKey.generate(curve=SECP256k1)
            public_key = private_key.get_verifying_key()

            user_data = {
                "username": username,
                "public_key": public_key.to_string().hex(),
                "private_key": private_key.to_string().hex(),
                "password": password,
                "role": role,
            }
            self.save_user_data(username, user_data)

        public_key_str = public_key.to_string().hex()

        # Proceed with signup
        data = {
            "username": username,
            "password": password,
            "role": role,
            "public_key": public_key_str,
        }
        url = f"{self.base_url}/signup"
        return requests.post(url, json=data)

    # Helper method for saving the user credentials to a file (used for the test cases below)
    def save_user_data(self, username, user_data):
        self.ensure_directory_exists()
        filename = os.path.join("testcredentials", f"{username}_keys.json")
        with open(filename, "w") as file:
            json.dump(user_data, file)

    # Helper method for loading the user credentials from a file (used for the test cases below)    
    def load_user_data(self, username):
        filename = os.path.join("testcredentials", f"{username}_keys.json")
        if not os.path.exists(filename):
            return None
        with open(filename, "r") as file:
            return json.load(file)

    # Helper method for logging in the user; used to contact the flask endpoint/pass the data to it
    def login_user(self, username, password):
        # Load user data
        user_data = self.load_user_data(username)
        if not user_data:
            print("User data not found.")
            return None

        # Extract keys from user data
        self.private_key = SigningKey.from_string(
            bytes.fromhex(user_data["private_key"]), curve=SECP256k1
        )
        self.public_key = VerifyingKey.from_string(
            bytes.fromhex(user_data["public_key"]), curve=SECP256k1
        )

        # Proceed with login
        data = {"username": username, "password": password}
        url = f"{self.base_url}/login"
        return requests.post(url, json=data)

    # Helper method for udating the user permission; used to contact the flask endpoint/pass the data to it
    def update_user(self, update_data):
        url = f"{self.base_url}/update_user"
        return requests.post(url, json=update_data)

    # Helper method to mine blocks; used to contact the flask endpoint/pass the data to it
    def mine_block(self):
        url = f"{self.base_url}/mine"
        return requests.get(url)

    # Helper method to add health care records; used to contact the flask endpoint/pass the data to it
    def add_healthcare_record(
        self, patient_username, provider_username, record, from_address, signature
    ):
        data = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "record": record,
            "from_address": from_address,
            "signature": signature,
        }
        url = f"{self.base_url}/add_healthcare_record"
        return requests.post(url, json=data)
   
    # Helper method to get/read health care records; used to contact the flask endpoint/pass the data to it
    def get_healthcare_record(self, patient_username, requester_address):
        url = f"{self.base_url}/get_healthcare_record/{patient_username}"
        params = {"requester_address": requester_address}
        return requests.get(url, params=params)

    # Helper method to update health care records; used to contact the flask endpoint/pass the data to it
    def update_healthcare_record(
        self, patient_username, provider_username, updated_data, from_address, signature
    ):
        data = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "updated_data": updated_data,
            "from_address": from_address,
            "signature": signature,
        }
        url = f"{self.base_url}/update_healthcare_record"
        return requests.post(url, json=data)

    # Helper method to signup the user/test the signup
    def signup_and_test_user(self, username, password, role):
        signup_response = self.signup_user(username, password, role)
        if signup_response.status_code != 201:
            print(
                f"Signup Error for {role}:",
                signup_response.status_code,
                signup_response.text,
            )
        else:
            print(f"Signup Successful for {role}!")

        mine_response = self.mine_block()
        if mine_response.status_code != 200:
            print(
                f"Mining Error after {role} Signup:",
                mine_response.status_code,
                mine_response.text,
            )

    # Helper method to allow the patient to grant consent to a healthcare provider; used to contact the flask endpoint/pass the data to it
    def grant_consent(
        self,
        patient_username,
        provider_username,
        provider_public_key,
        patient_private_key,
    ):
        data = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "provider_public_key": provider_public_key,
            "patient_public_key": patient_private_key.get_verifying_key()
            .to_string()
            .hex(),
        }
        url = f"{self.base_url}/grant_consent"
        response = requests.post(url, json=data)

        print(f"Granting Consent from '{patient_username}' to '{provider_username}'")
        print(f"Grant Consent Response Status Code: {response.status_code}")
        if response.status_code == 201:
            print("Consent granted successfully.\n")
        else:
            print("Failed to grant consent.")
            print(
                f"Response Message: {response.json().get('message', 'No message available')}"
            )

        return response

    # Helper method to allow the patient to revoke consent of a healthcare provider; used to contact the flask endpoint/pass the data to it
    def revoke_consent(
        self,
        patient_username,
        provider_username,
        provider_public_key,
        patient_private_key,
    ):
        data = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "provider_public_key": provider_public_key,
            "patient_public_key": patient_private_key.get_verifying_key()
            .to_string()
            .hex(),
        }
        url = f"{self.base_url}/revoke_consent"
        response = requests.post(url, json=data)

        print(f"Revoking Consent from '{patient_username}' for '{provider_username}'")
        print(f"Revoke Consent Response Status Code: {response.status_code}")
        if response.status_code == 201:
            print("Consent revoked successfully.\n")
        else:
            print("Failed to revoke consent.")
            print(
                f"Response Message: {response.json().get('message', 'No message available')}"
            )

        return response

    # Helper method to add health care record and mine it; used to contact the flask endpoint/pass the data to it
    def add_and_mine_record(
        self,
        patient_username,
        provider_username,
        record,
        provider_public_key,
        provider_private_key,
        expect_success=True,
    ):
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        signature = provider_private_key.sign(record_digest.encode()).hex()
        add_record_response = self.add_healthcare_record(
            patient_username, provider_username, record, provider_public_key, signature
        )
        print(f"Add Record Response: {add_record_response.status_code}")
        if expect_success:
            assert add_record_response.status_code == 201
        else:
            assert add_record_response.status_code == 400
        self.mine_block()

    # Helper method to get/read health care records and print them in the console/terminal; used to contact the flask endpoint/pass the data to it
    def get_and_print_record(
        self, patient_username, requester_public_key, expect_success=True
    ):
        get_record_response = self.get_healthcare_record(
            patient_username, requester_public_key
        )
        print(f"Get Record Response: {get_record_response.status_code}")
        if expect_success:
            assert get_record_response.status_code == 200
        else:
            assert (
                get_record_response.status_code == 404
                or get_record_response.status_code == 401
            )

    # Helper method to test the nurse role; used to contact the flask endpoint/pass the data to it
    def test_nurse_role(
        self, patient_username, nurse_username, nurse_public_key, nurse_private_key
    ):
        # Nurse tries to add a record (fails due to permissions)
        record = {"data": "nurse's healthcare data"}
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        nurse_signature = nurse_private_key.sign(record_digest.encode()).hex()

        response = self.add_healthcare_record(
            patient_username, nurse_username, record, nurse_public_key, nurse_signature
        )
        print(f"Nurse add record response: {response.status_code}")
        assert response.status_code == 401  # Unauthorized action

        # Nurse tries to read a record (fails without consent, passes when given consent)
        response = self.get_healthcare_record(patient_username, nurse_public_key)
        print(f"Nurse read record response: {response.status_code}")

    # Helper method to test the admin role; used to contact the flask endpoint/pass the data to it
    def test_admin_role(
        self, patient_username, admin_username, admin_public_key, admin_private_key
    ):
        # Admin tries to add a record (expected to succeed)
        record = {"data": "admin's healthcare data"}
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        admin_signature = admin_private_key.sign(record_digest.encode()).hex()

        response = self.add_healthcare_record(
            patient_username, admin_username, record, admin_public_key, admin_signature
        )
        self.mine_block()
        print(
            f"Admin add record response: {response.status_code}, Detail: {response.text}"
        )
        assert (
            response.status_code == 201
        ), f"Unexpected response code: {response.status_code}, Detail: {response.text}"

        # Admin tries to read a record (expected to succeed)
        response = self.get_healthcare_record(patient_username, admin_public_key)
        print(
            f"Admin read record response: {response.status_code}, Detail: {response.text}"
        )
        assert (
            response.status_code == 200
        ), f"Unexpected response code: {response.status_code}, Detail: {response.text}"

    # Helper method to test the nurse role; used to contact the flask endpoint/pass the data to it
    def test_doctor_role(
        self, patient_username, doctor_username, doctor_public_key, doctor_private_key
    ):
        # Doctor tries to add a record (expected to succeed)
        record = {"data": "doctor's healthcare data"}
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        doctor_signature = doctor_private_key.sign(
            record_digest.encode()
        ).hex()  # Generate the signature

        response = self.add_healthcare_record(
            patient_username,
            doctor_username,
            record,
            doctor_public_key,
            doctor_signature,
        )
        self.mine_block()
        print(f"Doctor add record response: {response.status_code}, Detail: {response.text}")
        assert response.status_code == 201

        # Doctor tries to read a record (expected to succeed)
        response = self.get_healthcare_record(patient_username, doctor_public_key)
        print(f"Doctor read record response: {response.status_code}, Detail: {response.text}")
        assert response.status_code == 200

    # Helper method to grant consent and mine the transaction; used to contact the flask endpoint/pass the data to it
    def grant_and_mine_consent(
        self,
        patient_username,
        provider_username,
        provider_public_key,
        patient_private_key,
    ):
        self.grant_consent(
            patient_username,
            provider_username,
            provider_public_key,
            patient_private_key,
        )
        self.mine_block()
        time.sleep(2)

    # Helper method to login the user/test the login    
    def test_login_user(self, username, password):
        response = self.login_user(username, password)
        assert (
            response.status_code == 200
        ), f"Failed to log in with correct credentials for user {username}"
        print(f"--- Testing User Login for '{username}' ---")
        print(f"Login Response Status Code: {response.status_code}")
        if response.status_code == 200:
            print("Login successful.\n")
        else:
            print("Login failed.")
            print(
                f"Response Message: {response.json().get('message', 'No message available')}"
            )

    # Helper method to test the admin only actions (updating user roles); used to contact the flask endpoint/pass the data to it
    def test_admin_only_action(self, username_to_update, admin_public_key):
        # Example admin action: updating a user's role (in this case updating their own role)
        updated_data = {
            "admin_username": username_to_update,
            "admin_public_key": admin_public_key,
            "username": username_to_update,
            "public_key": admin_public_key,
            "updated_data": {"role": "Administrator"},
        }

        # Update user endpoint
        url = f"{self.base_url}/update_user"
        response = requests.post(url, json=updated_data)

        print(f"Admin-only action response: {response.status_code}, {response.text}")
        assert response.status_code == 201, "Failed to perform admin-only action"

    # Helper method to update health care records and mine the transaction; used to contact the flask endpoint/pass the data to it    
    def update_and_mine_record(
        self,
        patient_username,
        provider_username,
        updated_record,
        provider_public_key,
        provider_private_key,
    ):
        # Prepare the updated record
        record_string = json.dumps(updated_record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        signature = provider_private_key.sign(record_digest.encode()).hex()

        # Update healthcare record endpoint
        url = f"{self.base_url}/update_healthcare_record"
        data = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "updated_data": updated_record,
            "from_address": provider_public_key,
            "signature": signature,
        }
        update_response = requests.post(url, json=data)
        print(
            f"Update record response: {update_response.status_code}, {update_response.text}"
        )
        assert update_response.status_code == 200, "Failed to update healthcare record"

        # Mine a block to include the transaction
        mine_response = self.mine_block()
        print(f"Mine block response: {mine_response.status_code}, {mine_response.text}")
        assert mine_response.status_code == 200, "Failed to mine a block"

    # Testing patient consent system with a single provider; calls the helper methods above to complete a series of tests
    def test_patient_consent_system_single_provider(self):
        print("\n--- Testing Patient Consent System with a Single Provider ---")
        patient_username = "patientuser"
        provider_username = "doctoruser"
        self.signup_and_test_user(patient_username, "patientpassword", "Patient")
        self.signup_and_test_user(provider_username, "doctorpassword", "Doctor")

        patient_data = self.load_user_data(patient_username)
        provider_data = self.load_user_data(provider_username)
        patient_private_key = SigningKey.from_string(
            bytes.fromhex(patient_data["private_key"]), curve=SECP256k1
        )
        provider_private_key = SigningKey.from_string(
            bytes.fromhex(provider_data["private_key"]), curve=SECP256k1
        )
        provider_public_key = provider_data["public_key"]

        # Attempt to add a record before granting consent
        print("\n--- Attempting to Add Record Before Granting Consent ---")
        record = {"data": "attempt before granting consent"}
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        signature = provider_private_key.sign(record_digest.encode()).hex()
        add_record_before_consent_response = self.add_healthcare_record(
            patient_username, provider_username, record, provider_public_key, signature
        )
        print(
            f"Add Record Before Granting Consent Response: {add_record_before_consent_response.status_code}"
        )
        self.mine_block()

        # Grant consent
        print("\n--- Granting Consent from Patient to Provider ---")
        self.grant_consent(
            patient_username,
            provider_username,
            provider_public_key,
            patient_private_key,
        )
        self.mine_block()

        # Test adding multiple records before revoking consent
        for i in range(3):
            record = {"data": f"provider's healthcare data {i}"}
            record_string = json.dumps(record, sort_keys=True)
            record_digest = hashlib.sha256(record_string.encode()).hexdigest()
            signature = provider_private_key.sign(record_digest.encode()).hex()
            add_record_response = self.add_healthcare_record(
                patient_username,
                provider_username,
                record,
                provider_public_key,
                signature,
            )
            print(f"Add Record {i} Response: {add_record_response.status_code}")
            self.mine_block()

            get_record_response = self.get_healthcare_record(
                patient_username, provider_public_key
            )
            print(
                f"Get Record {i} Response: {get_record_response.status_code}, Data: {get_record_response.json()}"
            )

        # Revoke consent
        print("\n--- Revoking Consent from Patient to Provider ---")
        self.revoke_consent(
            patient_username,
            provider_username,
            provider_public_key,
            patient_private_key,
        )
        self.mine_block()

        # Attempt to add a record after revoking consent
        record = {"data": "attempt after revoking consent"}
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        signature = provider_private_key.sign(record_digest.encode()).hex()
        add_record_denied_response = self.add_healthcare_record(
            patient_username, provider_username, record, provider_public_key, signature
        )
        print(
            f"Add Record After Revoking Consent Response: {add_record_denied_response.status_code}"
        )
        self.mine_block()

        # Attempt to retrieve the record after revoking consent
        get_record_denied_response = self.get_healthcare_record(
            patient_username, provider_public_key
        )
        print(
            f"Get Record After Revoking Consent Response: {get_record_denied_response.status_code}"
        )

        # Re-grant consent and add another record
        print("\n--- Re-Granting Consent from Patient to Provider ---")
        self.grant_consent(
            patient_username,
            provider_username,
            provider_public_key,
            patient_private_key,
        )
        self.mine_block()

        record = {"data": "new data after re-granting consent"}
        record_string = json.dumps(record, sort_keys=True)
        record_digest = hashlib.sha256(record_string.encode()).hexdigest()
        signature = provider_private_key.sign(record_digest.encode()).hex()
        add_record_response = self.add_healthcare_record(
            patient_username, provider_username, record, provider_public_key, signature
        )
        print(
            f"Add Record Response After Re-Granting Consent: {add_record_response.status_code}"
        )
        self.mine_block()

        # Revoke consent
        print("\n--- Revoking Consent from Patient to Provider ---")
        self.revoke_consent(
            patient_username,
            provider_username,
            provider_public_key,
            patient_private_key,
        )
        self.mine_block()

    # Testing patient consent system with multiple providers; calls the helper methods above to complete a series of tests
    def test_patient_consent_system_multiple_providers(self):
        print("\n--- Testing Patient Consent System with Multiple Providers---")
        patient_username = "patientuser1"
        doctor1_username = "doctoruser1"
        doctor2_username = "doctoruser2"

        # Sign up patient and two doctors
        self.signup_and_test_user(patient_username, "patientpassword", "Patient")
        self.signup_and_test_user(doctor1_username, "doctorpassword1", "Doctor")
        self.signup_and_test_user(doctor2_username, "doctorpassword2", "Doctor")

        # Load user data
        patient_data = self.load_user_data(patient_username)
        doctor1_data = self.load_user_data(doctor1_username)
        doctor2_data = self.load_user_data(doctor2_username)

        # Extract keys
        patient_private_key = SigningKey.from_string(
            bytes.fromhex(patient_data["private_key"]), curve=SECP256k1
        )
        doctor1_private_key = SigningKey.from_string(
            bytes.fromhex(doctor1_data["private_key"]), curve=SECP256k1
        )
        doctor2_private_key = SigningKey.from_string(
            bytes.fromhex(doctor2_data["private_key"]), curve=SECP256k1
        )

        # Grant consent to Doctor 1 only
        print("\n--- Granting Consent from Patient to Doctor 1 ---")
        self.grant_consent(
            patient_username,
            doctor1_username,
            doctor1_data["public_key"],
            patient_private_key,
        )
        self.mine_block()

        # Doctor 1 adds a record (should be successful)
        record = {"data": "doctor1's healthcare data"}
        print("\n--- Doctor 1 adding records (has been granted consent) ---")
        self.add_and_mine_record(
            patient_username,
            doctor1_username,
            record,
            doctor1_data["public_key"],
            doctor1_private_key,
        )

        # Doctor 2 attempts to add a record (should fail)
        record = {"data": "doctor2's healthcare data"}
        print("\n--- Doctor 2 adding records (has not been granted consent) ---")
        self.add_and_mine_record(
            patient_username,
            doctor2_username,
            record,
            doctor2_data["public_key"],
            doctor2_private_key,
            expect_success=False,
        )

        # Doctor 2 attempts to view record (should fail)
        print("\n--- Doctor 2 viewing records (has not been granted consent) ---")
        self.get_and_print_record(
            patient_username, doctor2_data["public_key"], expect_success=False
        )

        # Revoke consent
        print("\n--- Revoking Consent from Patient to Provider ---")
        self.revoke_consent(
            patient_username,
            doctor1_username,
            doctor1_data["public_key"],
            patient_private_key,
        )
        self.mine_block()

    # Testing Role Based Access Control; calls the helper methods above to complete a series of tests
    def test_role_based_access_control(self):
        print("\n--- Testing Role Based Access Control ---")
        patient_username = "patientuser_rbac"
        nurse_username = "nurseuser_rbac"
        admin_username = "adminuser_rbac"
        doctor_username = "doctoruser_rbac"

        # Sign up patient, nurse, admin, and doctor
        self.signup_and_test_user(patient_username, "patientpassword", "Patient")
        self.signup_and_test_user(nurse_username, "nursepassword", "Nurse")
        self.signup_and_test_user(admin_username, "adminpassword", "Administrator")
        self.signup_and_test_user(doctor_username, "doctorpassword", "Doctor")

        # Extract private and public keys for all roles
        patient_data = self.load_user_data(patient_username)
        doctor_data = self.load_user_data(doctor_username)
        nurse_data = self.load_user_data(nurse_username)
        admin_data = self.load_user_data(admin_username)
        patient_private_key = SigningKey.from_string(
            bytes.fromhex(patient_data["private_key"]), curve=SECP256k1
        )
        doctor_private_key = SigningKey.from_string(
            bytes.fromhex(doctor_data["private_key"]), curve=SECP256k1
        )
        nurse_private_key = SigningKey.from_string(
            bytes.fromhex(nurse_data["private_key"]), curve=SECP256k1
        )
        admin_private_key = SigningKey.from_string(
            bytes.fromhex(admin_data["private_key"]), curve=SECP256k1
        )
        doctor_public_key = doctor_data["public_key"]
        nurse_public_key = nurse_data["public_key"]
        admin_public_key = admin_data["public_key"]

        print("\n--- Granting Consent from Patient to Doctor and Admin---")
        self.grant_and_mine_consent(
            patient_username, doctor_username, doctor_public_key, patient_private_key
        )
        self.grant_and_mine_consent(
            patient_username, admin_username, admin_public_key, patient_private_key
        )

        # Test different roles
        print("\n--- Nurse Attempting to Add and Read Patient without Consent ---")
        self.test_nurse_role(
            patient_username, nurse_username, nurse_public_key, nurse_private_key
        )
        
        print("\n--- Granting Consent from Patient to Nurse---")
        self.grant_and_mine_consent(
            patient_username, nurse_username, nurse_public_key, patient_private_key
        )
        print("\n--- Nurse Attempting to Add and Read Patient with Consent ---")
        self.test_nurse_role(
            patient_username, nurse_username, nurse_public_key, nurse_private_key
        )
        
        print("\n--- Admin Attempting to Add and Read Patient with Consent ---")
        self.test_admin_role(
            patient_username, admin_username, admin_public_key, admin_private_key
        )
        
        print("\n--- Doctor Attempting to Add and Read Patient with Consent ---")
        self.test_doctor_role(
            patient_username, doctor_username, doctor_public_key, doctor_private_key
        )

    # Testing User Login with Role Update and Data Entry Update; calls the helper methods above to complete a series of tests
    def test_user_login_role_update_and_data_entry(self):
        print("\n--- Testing User Login with Role Update and Data Entry Update---")
        # Create users
        admin_username = "adminuser"
        patient_username = "patientuser"
        doctor_username = "doctoruser"

        # Sign up an admin, a patient, and a doctor
        self.signup_and_test_user(admin_username, "adminpassword", "Administrator")
        self.signup_and_test_user(patient_username, "patientpassword", "Patient")
        self.signup_and_test_user(doctor_username, "doctorpassword", "Doctor")

        # Load user data
        admin_data = self.load_user_data(admin_username)
        patient_data = self.load_user_data(patient_username)
        doctor_data = self.load_user_data(doctor_username)

        # Extract keys
        admin_private_key = SigningKey.from_string(
            bytes.fromhex(admin_data["private_key"]), curve=SECP256k1
        )
        patient_private_key = SigningKey.from_string(
            bytes.fromhex(patient_data["private_key"]), curve=SECP256k1
        )
        doctor_private_key = SigningKey.from_string(
            bytes.fromhex(doctor_data["private_key"]), curve=SECP256k1
        )
        doctor_public_key = doctor_data["public_key"]
        patient_public_key = patient_data["public_key"]
        admin_public_key = admin_data["public_key"]

        # Test User Login
        self.test_login_user(patient_username, "patientpassword")

        # Update Doctor's Role (Admin changing Doctor's role)
        updated_data = {
            "admin_username": admin_username,
            "admin_public_key": admin_public_key,
            "username": doctor_username, 
            "public_key": doctor_public_key,
            "updated_data": {"role": "Administrator"}
        }
        print("\n--- Admin updating Doctor's role to admin ---")
        update_role_response = self.update_user(updated_data)
        self.mine_block()
        print(f"Update Role Response: {update_role_response.status_code}")
        print(f"\nUpdate Role Response: {update_role_response.text}")
        assert update_role_response.status_code == 201, "Failed to update user role"

        # Testing Updated Role Permissions (Admin performing an action)
        print("\n--- Testing updated role permissions for the doctor to change role ---")
        self.test_admin_only_action(doctor_username, doctor_public_key)
        self.mine_block()

        # Grant consent from the patient to the doctor
        print("\n--- Granting Consent from Patient to Doctor ---")
        self.grant_consent(
            patient_username, doctor_username, doctor_public_key, patient_private_key
        )
        self.mine_block()

        # Add a healthcare record for the patient by the doctor
        record = {"data": "doctor's healthcare data for patient"}
        print("\n--- Doctor Adding Healthcare Record for Patient ---")
        self.add_and_mine_record(
            patient_username,
            doctor_username,
            record,
            doctor_public_key,
            doctor_private_key,
        )

        # Update the healthcare record for the patient by the doctor
        updated_record = {"data": "doctor's updated healthcare data for patient"}
        print("\n--- Doctor Updating Healthcare Record for Patient ---")
        self.update_and_mine_record(
            patient_username,
            doctor_username,
            updated_record,
            doctor_public_key,
            doctor_private_key,
        )

        # Check updated record
        print("\n--- Checking Updated Record for Patient ---")
        self.get_and_print_record(patient_username, doctor_public_key)

        # Patient reads their own record
        print("\n--- Patient Reading Their Own Record ---")
        patient_read_response = self.get_healthcare_record(
            patient_username, patient_public_key
        )
        print(
            f"Patient Read Record Response: {patient_read_response.status_code}, Data: {patient_read_response.json() if patient_read_response.status_code == 200 else 'N/A'}"
        )

        # Revoke consent
        print("\n--- Revoking Consent from Patient to Provider ---")
        self.revoke_consent(
            patient_username, doctor_username, doctor_public_key, patient_private_key
        )
        self.mine_block()

    # Method which is called to run the four main tests
    def run_tests(self):
        # Testing patient consent system with a single provider
        self.test_patient_consent_system_single_provider()

        # Testing patient consent system with multiple providers
        self.test_patient_consent_system_multiple_providers()

        # Testing Role Based Access Control
        self.test_role_based_access_control()

        # Testing User Login with Role Update and Data Entry Update
        self.test_user_login_role_update_and_data_entry()

# Defining the main funciton. Will need to update the port number of adjusted in the main flask server (app.py)
def main():
    base_url = "http://127.0.0.1:5001"
    tester = BlockchainTester(base_url)
    tester.run_tests()

# Running the main method
if __name__ == "__main__":
    main()
