import hashlib
import time
import json
import requests
from urllib.parse import urlparse


# Class for defining the block and computing the hash
# Contains the individual block struck and the methof for computing the hash of each block
class Block:
    def __init__(
        self, index, transactions, timestamp, previous_hash, nonce=0, hash=None
    ):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash

    # The method for computing the hash for the block
    def compute_hash(self):
        block_data = self.__dict__.copy()
        block_data.pop("hash", None)
        block_string = json.dumps(block_data, sort_keys=True)
        hash_result = hashlib.sha256(block_string.encode()).hexdigest()
        # Print statement used for debugging purposes to check the hash computation
        # print(f"Computing Hash: Block String = {block_string}, Hash = {hash_result}")
        return hash_result


# The class which contains the blockchain related methods
class Blockchain:
    # Blockchain initialization/setup
    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.nodes = set()
        self.create_genesis_block()

    # The method to save the blockchain to a file (used for data persistance)
    def save_chain_to_file(self, filename="blockchain.json"):
        chain_data = [block.__dict__ for block in self.chain]
        with open(filename, "w") as file:
            json.dump(chain_data, file, indent=4)
        print(f"Blockchain saved to {filename}")

    # The method to load the blockchain from a file when server is started up (used for data persistance)
    def load_chain_from_file(self, filename="blockchain.json"):
        try:
            with open(filename, "r") as file:
                chain_data = json.load(file)
            self.chain = []
            for block_data in chain_data:
                block = Block(
                    index=block_data["index"],
                    transactions=block_data["transactions"],
                    timestamp=block_data["timestamp"],
                    previous_hash=block_data["previous_hash"],
                    nonce=block_data["nonce"],
                    hash=block_data["hash"],
                )
                self.chain.append(block)
            print(f"Blockchain loaded from {filename}")
        except FileNotFoundError:
            print(f"No existing blockchain found in {filename}. Starting new.")
            self.save_chain_to_file()

    # The method to create the genesis block (starter block) in the chain
    def create_genesis_block(self):
        # Using a fixed timestamp for the genesis block to ensure all nodes start with the same genesis block
        fixed_timestamp = 12345678
        genesis_block = Block(0, [], fixed_timestamp, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    # Last block (most recent) in the chain
    @property
    def last_block(self):
        return self.chain[-1]

    # The method for adding a new block to the chain
    def add_block(self, block, proof):
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        self.save_chain_to_file()
        return True

    # The method responsible for the proof of work
    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith("0000"):
            block.nonce += 1
            computed_hash = block.compute_hash()
            # Print statement used for debugging to check the proof of work (can generate a lot of output based on difficulty)
            # print(f"Trying nonce {block.nonce}: Hash {computed_hash}")

        print(f"Proof of work found: Nonce = {block.nonce}, Hash = {computed_hash}")
        return computed_hash

    # The method to check if the proof is valid
    def is_valid_proof(self, block, block_hash):
        computed_hash = block.compute_hash()
        valid_proof = block_hash.startswith("0000") and block_hash == computed_hash
        # Print statement for debugging purposes used to check the proof of work
        # print(f"Validating Proof of Work: Received Hash = {block_hash}, Computed Hash = {computed_hash}, Hash Valid = {valid_proof}")
        return valid_proof

    # The method for sending new transactions to the node
    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    # The method for mining outstanding transactions
    def mine(self):
        print("Mining process started.")
        if not self.unconfirmed_transactions:
            print("No unconfirmed transactions to mine.")
            return False

        last_block = self.last_block
        print(
            f"Processing {len(self.unconfirmed_transactions)} unconfirmed transactions."
        )

        # Process each transaction in unconfirmed_transactions
        for transaction in self.unconfirmed_transactions:
            if transaction.get("type") == "consent_update":
                # print for debugging purposes shows the transaction for consent update
                #print("Processing consent update transaction:", transaction)
                self.process_consent_transaction(transaction)

        new_block = Block(
            index=last_block.index + 1,
            transactions=self.unconfirmed_transactions,
            timestamp=time.time(),
            previous_hash=last_block.hash,
        )

        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            print(f"New block added at index {new_block.index}.")
            self.broadcast_block(new_block)
            self.unconfirmed_transactions = []
            return new_block.index
        else:
            print("Failed to add new block.")
            return False

    # The method to process consent related transactions
    def process_consent_transaction(self, transaction):
        print("Processing consent transaction:", transaction)

        # Check if the transaction is of type 'consent_update'
        if transaction.get("type") == "consent_update":
            # Extract relevant information from the transaction
            patient_username = transaction.get("patient_username")
            provider_username = transaction.get("provider_username")
            consent_action = transaction.get("consent_action")
            provider_public_key = transaction.get("provider_public_key")
            consents = transaction.get("consents", [])

            # Print out the details for debugging
            print(f"Consent Update Transaction Details:")
            print(f" - Patient Username: {patient_username}")
            print(f" - Provider Username: {provider_username}")
            print(f" - Consent Action: {consent_action}")
            print(f" - Provider Public Key: {provider_public_key}")
            print(f" - Consents: {consents}")

        else:
            # Handles other types of transactions
            print(
                f"Not a consent transaction. Transaction type: {transaction.get('type')}"
            )

    # The method to register additional nodes (computers)
    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts a URL without scheme (192.168.2.1:5000)'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("Invalid URL")

        # After registering the node, attempt to resolve conflicts
        chain_replaced = self.resolve_conflicts()
        if chain_replaced:
            self.save_chain_to_file()

    # The method for resolving conflicts between different nodes
    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        print("Resolving conflicts...")
        for node in neighbours:
            print(f"Contacting node {node} for chain...")
            response = requests.get(f"http://{node}/chain")

            if response.status_code == 200:
                length = response.json()["length"]
                chain = response.json()["chain"]

                if length > max_length:
                    max_length = length
                    new_chain = chain
                elif length == max_length:
                    current_chain_dict = json.dumps(
                        self.convert_chain_to_dict(self.chain), sort_keys=True
                    )
                    received_chain_dict = json.dumps(chain, sort_keys=True)
                    if current_chain_dict == received_chain_dict:
                        print(
                            "Chains are identical in length and content. No update required."
                        )
                        return False
                    else:
                        print(
                            "Same length but different content found in chain. Keeping current chain."
                        )
                        return False

        if new_chain:
            print("Found a longer valid chain. Replacing current chain.")
            self.chain = self.convert_to_blocks(new_chain)
            return True

        print("No longer valid chain found. Keeping current chain.")
        return False

    # Helper method to convert Block objects in self.chain to dictionaries
    def convert_chain_to_dict(self, chain):
        return [block.__dict__ for block in chain]

    # The method which converts a chain of dictionaries to a chain of Block objects
    def convert_to_blocks(self, chain_json):
        new_chain = []
        for block_data in chain_json:
            block = Block(
                block_data["index"],
                block_data["transactions"],
                block_data["timestamp"],
                block_data["previous_hash"],
                block_data["nonce"],
            )
            block.hash = block_data["hash"]
            new_chain.append(block)
        return new_chain

    # The method which broadcasts the mined block to other registered nodes
    def broadcast_block(self, block):
        for node in self.nodes:
            url = f"http://{node}/add_block"
            headers = {"Content-Type": "application/json"}
            data = json.dumps(block.__dict__)
            try:
                response = requests.post(url, headers=headers, data=data)
                if response.status_code != 201:
                    pass
            except requests.exceptions.RequestException as e:
                pass

    # The method gets the public key from the chain for a username
    def get_username_from_public_key(self, public_key):
        for block in reversed(self.chain):
            for transaction in block.transactions:
                if transaction.get("public_key") == public_key:
                    return transaction.get("username")
        return None
