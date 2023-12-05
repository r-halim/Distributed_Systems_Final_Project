from blockchain import Blockchain
from user import User


class BlockchainManager:
    def __init__(self, blockchain):
        self.blockchain = blockchain

    # Method user to authenticate the users credentials
    def authenticate_user(self, username, password):
        for block in reversed(self.blockchain.chain):
            for transaction in block.transactions:
                if (
                    transaction.get("type") == "user_registration"
                    and transaction.get("username") == username
                ):
                    stored_password = transaction.get("password")
                    return User.validate_password(password, stored_password)
        return None

    # Method used to get the latest user data. 
    # Ensures it gets the updated user status/role (if it has been updated by an admin)
    def get_latest_user_data(self, username):
        latest_registration = None
        latest_update = None

        for block in reversed(self.blockchain.chain):
            for transaction in block.transactions:
                if transaction.get("username") == username:
                    if transaction.get("type") == "user_registration":
                        latest_registration = transaction
                    elif transaction.get("type") == "user_update":
                        latest_update = transaction
                        break  # Stop the search after finding the latest user data

        # Merge the latest update with the registration data
        if latest_update:
            user_data = {**latest_registration, **latest_update, "role": latest_update.get("new_role")}
            return user_data
        else:
            return latest_registration