# Blockchain Integrated Healthcare Management System (BIHMS) Utilizing Smart Contracts

## Project Description
The project is designed to showcase a distributed healthcare information system that utilizes Blockchain and smart contracts.

## Prerequisites
Make sure you have Python installed on your system. You can download it from [Python's official website](https://www.python.org/).

## Setting Up a Virtual Environment

### Creating the Environment
1. Open your terminal.
2. Navigate to your project directory.
3. Run the following command to create a virtual environment named 'venv':
```
python3 -m venv venv
```

### Activating the Environment
- On Windows, run:
```
venv\Scripts\activate
```

- On macOS and Linux, run:
```
source venv/bin/activate
```

## Installing Dependencies

```bash
pip install Flask
pip install ecdsa
pip install requests
```

## Running the Application

After installing all necessary dependencies, you can run the application by following these steps:

1. Open the project folder in Visual Studio Code.
2. Launch the `app.py` Flask server. Note: If necessary, modify the port number to avoid conflicts with other services on your machine.
3. Execute `endToEndTesting.py` to initiate the test cases for the project.
4. Upon completion, inspect the `blockchain.json` file to review the created blockchain.
5. Check the `audit_log.json` file to view the generated audit log.

For a list of additional terminal commands, please refer to the `Terminal Commands.txt` file included in the project.

### Clearing the Blockchain
To reset the blockchain:
1. Delete the `blockchain.json` file.
2. Also, remove the `testcredentials` folder, which is generated when the testing file is run.

To set up and run the Flask server on multiple computers, follow these instructions after completing step 2:

- On each additional machine (node), execute the following command. Replace `IP.Address` and `port` with the appropriate values for the computer you want to register. Adjust the second port number if required:
  ```
  curl -X POST -H "Content-Type: application/json" -d '{"node_url": "http://IP.Address:port/"}' http://127.0.0.1:5001/register_node
  ```
- Repeat this process for each machine to establish a network of nodes.
