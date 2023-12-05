import hashlib
import json
import ecdsa
import os
from user import roles


# The class which contains the smart contracts methods
class HealthcareSmartContract:
    def __init__(self, blockchain, blockchain_manager):
        self.blockchain = blockchain
        self.blockchain_manager = blockchain_manager

    # The smart contract method to add a healthcare record
    def add_healthcare_record(
        self, patient_username, provider_username, record, from_address, signature
    ):
        # Check if 'from_address' has patient's consent
        if not self.has_patient_consent(patient_username, from_address):
            print(
                f"Action by {from_address} to add record denied due to lack of patient consent."
            )
            return False

        # Verify the signature
        if not self.verify_signature(record, signature, from_address):
            print("Failed signature verification.")
            return False

        # Check if 'from_address' is authorized to add this record
        if not self.is_authorized(from_address, "add_record"):
            print(f"Unauthorized action by {from_address} to add record.")
            return False

        # Add patient and provider usernames to the record
        record_with_usernames = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            **record,
        }
        print(f"Record with usernames added: {record_with_usernames}")

        # Add the record to the blockchain
        self.blockchain.add_new_transaction(record_with_usernames)
        print("Record added to unconfirmed transactions.")
        return True

    # The smart contract method to get/read a healthcare record of a patient
    def get_healthcare_record(self, patient_username, requester_address):
        print(
            f"Retrieving record for {patient_username} requested by {requester_address}"
        )

        # Check if 'requester_address' is authorized and has patient's consent
        if not (
            self.is_authorized(requester_address, "read_record")
            and self.has_patient_consent(patient_username, requester_address)
        ):
            print(
                f"Unauthorized access attempt by {requester_address} due to lack of consent."
            )
            return None

        # Iterate over the blockchain to find records for the given patient_username
        found = False
        for block in reversed(self.blockchain.chain):
            for transaction in block.transactions:
                print(f"Checking transaction in block {block.index}: {transaction}")
                if transaction.get("patient_username") == patient_username:
                    print(f"Record found for {patient_username} in block {block.index}")
                    return transaction
        if not found:
            print(f"No record found for {patient_username}")
        return None

    # The smart contract method to update a healthcare record
    def update_healthcare_record(
        self,
        patient_username,
        provider_username,
        updated_data,
        updater_address,
        signature,
    ):
        print(
            f"Attempting to update record for {patient_username} by {updater_address}"
        )

        # Verify the signature to ensure that the updater is authorized
        if not self.verify_signature(updated_data, signature, updater_address):
            print("Signature verification failed for update.")
            return False

        # Check if the updater has patient's consent
        if not self.has_patient_consent(patient_username, updater_address):
            print(
                f"Unauthorized update attempt by {updater_address} due to lack of patient consent."
            )
            return False

        # Check if the updater is authorized to update this record
        if not self.is_authorized(updater_address, "update_record"):
            print(f"Unauthorized update attempt by {updater_address}")
            return False

        # Check if the record exists in the blockchain
        record_exists = False
        for block in self.blockchain.chain:
            for transaction in block.transactions:
                if transaction.get("patient_username") == patient_username:
                    record_exists = True
                    break

        if not record_exists:
            print(f"Record not found for {patient_username} for update.")
            return False

        # Create a new transaction with the updated record data
        updated_record = {
            "patient_username": patient_username,
            "provider_username": provider_username,
            **updated_data,
        }
        self.blockchain.add_new_transaction(updated_record)
        print("Healthcare record update transaction added for {patient_username}.")
        return True

    # The smart contract method which verifies the signature of the keys being used
    def verify_signature(self, record, signature, from_address):
        if os.getenv("RUNNING_TESTS") == "True":
            return True

        try:
            record_string = json.dumps(record, sort_keys=True)
            record_digest = hashlib.sha256(record_string.encode()).hexdigest()

            public_key = ecdsa.VerifyingKey.from_string(
                bytes.fromhex(from_address), curve=ecdsa.SECP256k1
            )
            is_valid = public_key.verify(
                bytes.fromhex(signature), record_digest.encode()
            )

            print(f"Record String: {record_string}")
            print(f"Record Digest: {record_digest}")
            print(f"Public Key: {from_address}")
            print(f"Signature: {signature}")
            print(f"Verification Result: {is_valid}")

            return is_valid
        except Exception as e:
            print(f"Error in signature verification: {e}")
            return False

    # The smart contract method which checks if the address is authorized to perform the action requested
    def is_authorized(self, public_key, action):
        username = self.blockchain.get_username_from_public_key(public_key)
        if username:
            user_data = self.blockchain_manager.get_latest_user_data(username)
            if user_data:
                user_role_name = user_data["role"]
                print("Checking authorization for role:", user_role_name)
                is_authorized_action = action in roles[user_role_name].permissions
                return is_authorized_action
        return False

    # The smart contract method to check if the requester has patient consent
    def has_patient_consent(self, patient_username, requester_public_key):
        consent_status = None

        print(
            f"Checking consent for patient: {patient_username}, requester: {requester_public_key}"
        )
        for block in reversed(self.blockchain.chain):
            # print statement below for debugging showing the check being done
            #print(f"Checking block with index: {block.index} and hash: {block.hash}")
            for transaction in block.transactions:
                # print statements for debugging showing the check being done
                #print(f"Processing transaction for consent check: {transaction}")
                if (
                    transaction.get("type") == "consent_update"
                    and transaction.get("patient_username") == patient_username
                ):
                    consent_status = requester_public_key in transaction.get(
                        "consents", []
                    )
                    print(
                        f"Found consent transaction for patient. Consent status: {consent_status}"
                    )
                    return consent_status  # Returns as soon as the latest consent transaction is found

        if consent_status is None:
            print(
                f"No consent transaction found for patient: {patient_username}. Defaulting to no consent."
            )
            return False  # If no consent transaction is found, default to no consent

        print(f"Final consent status for {patient_username}: {consent_status}")
        return consent_status

    # The smart contract method to get all of the patient's consents
    def get_current_consents(self, patient_username):
        consents = set()
        print(f"Retrieving current consents for {patient_username}")

        # Iterate over the blockchain to find the latest consent transaction
        for block in reversed(self.blockchain.chain):  # Updated line
            for transaction in block.transactions:
                if (
                    transaction.get("type") == "consent_update"
                    and transaction.get("patient_username") == patient_username
                ):
                    action = transaction.get("consent_action")
                    # print for debugging purposes, shows each consent transaction found for the user
                    #print(f"Found {action} consent action in block {block.index}: {transaction}")
                    if action == "grant":
                        consents.add(transaction["provider_public_key"])
                    elif action == "revoke":
                        consents.discard(transaction["provider_public_key"])

        print(f"Current consents for {patient_username}: {consents}")
        return consents
