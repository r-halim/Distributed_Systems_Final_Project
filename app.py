import time
import json
from flask import Flask, request, jsonify
from smart_contracts import *
from blockchain import Blockchain, Block
from blockchain_manager import BlockchainManager
from user import User

AUDIT_LOG_DIR = "logs"
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, "audit_log.json")

# Ensure the logs directory exists
if not os.path.exists(AUDIT_LOG_DIR):
    os.makedirs(AUDIT_LOG_DIR)


# The method for adding the logs from each flask endpoint to the audit_log file
def log_audit_event(event_type, details):
    log_entry = {"timestamp": time.time(), "event_type": event_type, "details": details}
    with open(AUDIT_LOG_FILE, "a") as file:
        file.write(json.dumps(log_entry) + ",\n")


# Flask server intialization and flask endpoints defined
app = Flask(__name__)
blockchain = Blockchain()
blockchain_manager = BlockchainManager(blockchain)
healthcare_contract = HealthcareSmartContract(blockchain, blockchain_manager)

# Push context manually to app; loading chain from file during server startup (for data persistence)
with app.app_context():
    blockchain.load_chain_from_file()


# Sending a new transaction to the server
@app.route("/new_transaction", methods=["POST"])
def new_transaction():
    tx_data = request.get_json()
    blockchain.add_new_transaction(tx_data)
    log_audit_event("new_transaction", {"transaction": tx_data})
    return "Success", 201


# Getting the current blockchain printed
@app.route("/chain", methods=["GET"])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data), "chain": chain_data})


# Mining outstanding/unconfirmed transations
@app.route("/mine", methods=["GET"])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        log_audit_event("mining_failed", {"message": "No transactions to mine"})
        return jsonify({"message": "No transactions to mine"}), 200
    log_audit_event("block_mined", {"block_index": result})
    return jsonify({"message": f"Block #{result} is mined."}), 200


# Registering nodes together; Runs a resolve conflict method to ensure the chains match if registration is successful
@app.route("/register_node", methods=["POST"])
def register_node():
    node_data = request.get_json()
    node_url = node_data.get("node_url")
    if node_url is None:
        log_audit_event("register_node_failed", {"message": "Invalid data"})
        return "Invalid data", 400
    blockchain.register_node(node_url)
    log_audit_event("node_registered", {"node_url": node_url})
    return "Node registered successfully", 201


# Gets a list of currently registered nodes on the server
@app.route("/nodes", methods=["GET"])
def get_nodes():
    nodes_list = list(blockchain.nodes)
    log_audit_event("nodes_retrieved", {"nodes": nodes_list})
    return jsonify(nodes_list), 200


# Manually resolving conflicts between nodes
@app.route("/resolve_conflicts", methods=["GET"])
def resolve_conflicts():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {"message": "Our chain was replaced"}
        blockchain.save_chain_to_file()
        log_audit_event("chain_replaced", {"message": response})
    else:
        response = {"message": "Our chain is authoritative"}
        log_audit_event("chain_authoritative", {"message": response})
    return jsonify(response), 200


# Adding a block to the chain; when adding, it propoagates the block to all registered nodes.
# Once propagated, each registered node goes through a consensus mechanism to check the block index, 
# checks the previous hash then check the proof by running the is_valid_proof method
@app.route("/add_block", methods=["POST"])
def add_block():
    block_data = request.get_json()
    print("Received block data:", block_data)

    try:
        block = Block(
            block_data["index"],
            block_data["transactions"],
            block_data["timestamp"],
            block_data["previous_hash"],
            block_data["nonce"],
        )
        block.hash = block_data["hash"]

        # Check if the block index is correct
        if block.index != blockchain.last_block.index + 1:
            print(
                "Invalid index: Expected",
                blockchain.last_block.index + 1,
                "but got",
                block.index,
            )
            log_audit_event(
                "add_block_failed_invalid_block_index", {"block_index": block.index}
            )
            return jsonify({"error": "Incorrect index"}), 400

        # Check if the previous hash matches
        if block.previous_hash != blockchain.last_block.hash:
            print(
                "Invalid previous hash: Expected",
                blockchain.last_block.hash,
                "but got",
                block.previous_hash,
            )
            log_audit_event(
                "add_block_failed_invalid_previous_hash", {"block_index": block.index}
            )
            return jsonify({"error": "Incorrect previous hash"}), 400

        # Check if the proof of work is valid
        if not blockchain.is_valid_proof(block, block.hash):
            print("Invalid proof of work for block with index", block.index)
            log_audit_event(
                "add_block_failed_invalid_proof_of_work", {"block_index": block.index}
            )
            return jsonify({"error": "Invalid proof of work"}), 400

        # Add the block to the chain
        blockchain.chain.append(block)
        blockchain.save_chain_to_file()
        blockchain.unconfirmed_transactions = [
            tx
            for tx in blockchain.unconfirmed_transactions
            if tx not in block.transactions
        ]
        print("Block added to the chain with index", block.index)
        log_audit_event("block_added", {"block_index": block.index})
        return "Block added", 201

    except Exception as e:
        print("Error adding block:", str(e))
        log_audit_event("add_block_error", {"error": str(e), "block_data": block_data})
        return jsonify({"error": str(e)}), 400


# Signing up method
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    if (
        "username" in data
        and "password" in data
        and "role" in data
        and "public_key" in data
    ):
        # Check if the username already exists in the blockchain
        if blockchain_manager.get_latest_user_data(data["username"]):
            log_audit_event(
                "signup_failed",
                {"message": "Username already exists", "username": data["username"]},
            )
            return jsonify({"message": "Username already exists"}), 400

        hashed_password = User.hash_password(data["password"])
        new_user_transaction = {
            "username": data["username"],
            "password": hashed_password,
            "role": data["role"],
            "public_key": data["public_key"],
            "type": "user_registration",
        }
        blockchain.add_new_transaction(new_user_transaction)
        log_audit_event("signup_successful", {"username": data["username"]})
        return jsonify({"message": "User registration initiated"}), 201
    else:
        log_audit_event(
            "signup_failed", {"message": "Missing required fields", "data": data}
        )
        return jsonify({"message": "Missing required fields"}), 400


# Logging in method
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = blockchain_manager.authenticate_user(username, password)
    if user:
        # Login successful, return appropriate message
        log_audit_event("login_successful", {"username": username})
        return jsonify({"message": "Login successful"}), 200
    else:
        log_audit_event("login_failed", {"username": username})
        return jsonify({"message": "Invalid username or password"}), 401


# Updating user role
@app.route("/update_user", methods=["POST"])
def update_user():
    try:
        data = request.get_json()

        # Check if all required fields are present
        if "admin_username" in data and "admin_public_key" in data and "username" in data and "public_key" in data and "updated_data" in data:
            user_public_key = data["public_key"]
            admin_public_key = data["admin_public_key"]
            print("Required fields present. Admin Public Key:", admin_public_key, "User Public Key:", user_public_key)

            # Perform the authorization check
            is_authorized = healthcare_contract.is_authorized(admin_public_key, "update_user")
            print(f"Authorization check for admin with public key {admin_public_key}: {is_authorized}")
            if not is_authorized:
                print("Authorization failed. Admin not authorized to update.")
                return jsonify({"message": "Unauthorized: Only Administrators can update user roles"}), 403

            # Check if the user exists
            existing_user_data = blockchain_manager.get_latest_user_data(data["username"])
            if not existing_user_data:
                print("User does not exist in the system.")
                return jsonify({"message": "User does not exist"}), 404

            # Prepare the updated user data transaction
            updated_user_transaction = {
                "admin_username": data["admin_username"],
                "admin_public_key": admin_public_key,
                "username": data["username"],
                "user_public_key": user_public_key,
                "old_role": existing_user_data["role"],
                "new_role": data["updated_data"].get("role", existing_user_data["role"]),
                "type": "user_update",
            }

            # Add the new transaction to the blockchain
            blockchain.add_new_transaction(updated_user_transaction)
            print("New transaction added to the blockchain.")

            log_audit_event("user_update_successful", {"username": data["username"]})
            return jsonify({"message": "User update initiated"}), 201

        else:
            print("Missing required fields in the request.")
            return jsonify({"message": "Missing required fields"}), 400

    except Exception as e:
        # Log and return any exceptions that occur
        print(f"Exception occurred: {str(e)}")
        log_audit_event("user_update_error", {"error": str(e)})
        return jsonify({"error": str(e)}), 500


# Adding healthcare record for patient
@app.route("/add_healthcare_record", methods=["POST"])
def add_healthcare_record():
    data = request.get_json()
    patient_username = data["patient_username"]
    provider_username = data["provider_username"]
    record = data["record"]
    from_address = data["from_address"]
    signature = data["signature"]

    # Logging the add record request
    log_audit_event(
        "add_healthcare_record_request",
        {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "added_by": from_address,
        },
    )

    # Check if the from_address is authorized to add the record
    if not healthcare_contract.is_authorized(from_address, "add_record"):
        log_audit_event("add_record_unauthorized_access", {"added_by": from_address})
        return jsonify({"message": "Unauthorized action"}), 401

    # Attempt to add the healthcare record
    if healthcare_contract.add_healthcare_record(
        patient_username, provider_username, record, from_address, signature
    ):
        log_audit_event(
            "record_added",
            {
                "patient_username": patient_username,
                "provider_username": provider_username,
                "added_by": from_address,
            },
        )
        return jsonify({"message": "Record added successfully"}), 201
    else:
        log_audit_event(
            "record_addition_failed",
            {
                "patient_username": patient_username,
                "provider_username": provider_username,
                "added_by": from_address,
            },
        )
        return jsonify({"message": "Record addition failed"}), 400


# Reading/Getting the health record for the patient
@app.route("/get_healthcare_record/<patient_username>", methods=["GET"])
def get_healthcare_record(patient_username):
    requester_address = request.args.get("requester_address")

    # Logging the get record request
    log_audit_event(
        "get_healthcare_record_request",
        {"patient_username": patient_username, "requester_address": requester_address},
    )

    # Check if the requester is the patient themselves
    if patient_username == healthcare_contract.blockchain.get_username_from_public_key(
        requester_address
    ):
        print(f"Patient {patient_username} is requesting their own record.")
        action = "read_own_record"
    else:
        print(
            f"Requester {requester_address} is not the patient. Checking for consent."
        )
        action = "read_record"
        # Check for consent if the requester is not the patient
        if not healthcare_contract.has_patient_consent(
            patient_username, requester_address
        ):
            log_audit_event(
                "get_record_unauthorized_access",
                {
                    "patient_username": patient_username,
                    "requester_address": requester_address,
                },
            )
            return jsonify({"message": "Access denied: No consent"}), 401

    # Check if the requester is authorized to access the record
    if not healthcare_contract.is_authorized(requester_address, action):
        log_audit_event(
            "get_record_unauthorized_access",
            {
                "patient_username": patient_username,
                "requester_address": requester_address,
            },
        )
        return jsonify({"message": "Unauthorized action"}), 401

    # Attempt to retrieve the healthcare record
    record_found = False
    for block in reversed(healthcare_contract.blockchain.chain):
        for transaction in block.transactions:
            if transaction.get("patient_username") == patient_username:
                print(f"Record match found in block {block.index}: {transaction}")
                record_found = True
                log_audit_event(
                    "record_retrieved",
                    {
                        "patient_username": patient_username,
                        "requester_address": requester_address,
                        "block_index": block.index,
                    },
                )
                return jsonify(transaction), 200

    if not record_found:
        print(f"No healthcare record found for patient: {patient_username}")
        log_audit_event(
            "get_record_failed",
            {
                "patient_username": patient_username,
                "requester_address": requester_address,
            },
        )
        return jsonify({"message": "Healthcare record not found"}), 404


# Updating health care record for a patient
@app.route("/update_healthcare_record", methods=["POST"])
def update_healthcare_record():
    data = request.get_json()
    patient_username = data["patient_username"]
    provider_username = data["provider_username"]
    updated_data = data["updated_data"]
    from_address = data["from_address"]
    signature = data["signature"]

    # Logging the update record request
    log_audit_event(
        "update_healthcare_record_request",
        {
            "patient_username": patient_username,
            "provider_username": provider_username,
            "updater_address": from_address,
        },
    )

    # Check if the updater is authorized to update the record
    if not healthcare_contract.is_authorized(from_address, "update_record"):
        log_audit_event(
            "update_record_unauthorized_access",
            {"patient_username": patient_username, "updater_address": from_address},
        )
        return jsonify({"message": "Unauthorized action"}), 401

    # Attempt to update the healthcare record
    if healthcare_contract.update_healthcare_record(
        patient_username, provider_username, updated_data, from_address, signature
    ):
        log_audit_event(
            "record_updated",
            {
                "patient_username": patient_username,
                "provider_username": provider_username,
                "updater_address": from_address,
            },
        )
        return jsonify({"message": "Record updated successfully"}), 200
    else:
        log_audit_event(
            "update_record_failed",
            {
                "patient_username": patient_username,
                "provider_username": provider_username,
                "updater_address": from_address,
            },
        )
        return jsonify({"message": "Record update failed"}), 400


# Method allowing the patient to grant consent to a provider
@app.route("/grant_consent", methods=["POST"])
def grant_consent():
    data = request.get_json()
    patient_username = data["patient_username"]
    provider_username = data["provider_username"]
    provider_public_key = data["provider_public_key"]
    patient_public_key = data["patient_public_key"]

    # Authenticate the patient
    if not healthcare_contract.is_authorized(patient_public_key, "grant_consent"):
        log_audit_event(
            "grant_consent_unauthorized",
            {
                "patient_username": patient_username,
                "provider_username": provider_username,
            },
        )
        return jsonify({"message": "Unauthorized action"}), 401

    # Gets current patient's consent list, adds the providers public key that has been granted
    current_consents = healthcare_contract.get_current_consents(patient_username)
    current_consents.add(provider_public_key)

    # Update the patient's consent list with provider's public key
    consent_transaction = {
        "patient_username": patient_username,
        "provider_username": provider_username,
        "consent_action": "grant",
        "provider_public_key": provider_public_key,
        "type": "consent_update",
        "consents": list(current_consents),
    }
    blockchain.add_new_transaction(consent_transaction)
    log_audit_event(
        "consent_granted",
        {"patient_username": patient_username, "provider_username": provider_username},
    )
    return jsonify({"message": "Consent granted successfully"}), 201


# Method allowing the patient to revoke consent from a provider
@app.route("/revoke_consent", methods=["POST"])
def revoke_consent():
    data = request.get_json()
    patient_username = data["patient_username"]
    provider_username = data["provider_username"]
    provider_public_key = data["provider_public_key"]
    patient_public_key = data["patient_public_key"]

    # Authenticate the patient
    if not healthcare_contract.is_authorized(patient_public_key, "revoke_consent"):
        log_audit_event(
            "revoke_consent_unauthorized",
            {
                "patient_username": patient_username,
                "provider_username": provider_username,
            },
        )
        return jsonify({"message": "Unauthorized action"}), 401

    # Gets current patient's consent list, drops the providers public key that has been revoked
    current_consents = healthcare_contract.get_current_consents(patient_username)
    current_consents.discard(provider_public_key)

    # Update the patient's consent list with provider's public key
    consent_transaction = {
        "patient_username": patient_username,
        "provider_username": provider_username,
        "consent_action": "revoke",
        "provider_public_key": provider_public_key,
        "type": "consent_update",
        "consents": list(current_consents),
    }
    blockchain.add_new_transaction(consent_transaction)
    log_audit_event(
        "consent_revoked",
        {"patient_username": patient_username, "provider_username": provider_username},
    )
    return jsonify({"message": "Consent revoked successfully"}), 201


# Server startup
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
