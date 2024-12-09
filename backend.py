from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

API_KEY = "secure_api_key"  # Store in an environment variable in production

def require_api_key(func):
    """Decorator to enforce API key validation."""
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if api_key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper
# Dummy in-memory database for demonstration purposes
wallet_data = {}
token_db = {
    # Example wallet: token mappings
    # "wallet_address_1": "token_address_1"
}

@app.route('/wallet', methods=['POST'])
@require_api_key
def manage_wallet():
    """Handle wallet connection or disconnection."""
    data = request.get_json()
    action = data.get("action")
    wallet_address = data.get("wallet_address")

    if action == "connect":
        if not wallet_address:
            return jsonify({"error": "Wallet address is required."}), 400
        wallet_data["connected_wallet"] = wallet_address
        print(f"Wallet connected: {wallet_address}")
        return jsonify({"message": "Wallet connected successfully.", "wallet_address": wallet_address}), 200

    elif action == "disconnect":
        if "connected_wallet" in wallet_data:
            wallet_data.pop("connected_wallet", None)
            print("Wallet disconnected.")
            return jsonify({"message": "Wallet disconnected successfully."}), 200
        return jsonify({"error": "No wallet connected."}), 400

    return jsonify({"error": "Invalid action."}), 400


@app.route('/check_token/<wallet_address>', methods=['GET'])
def check_token(wallet_address):
    """Check if a token is associated with the given wallet address."""
    token_address = token_db.get(wallet_address)
    if token_address:
        return jsonify({"token_exists": True, "token_address": token_address}), 200
    else:
        return jsonify({"token_exists": False}), 200

@app.route('/connect_phantom', methods=['GET'])
def connect_phantom():
    """Simulate Phantom wallet connection."""
    return jsonify({"message": "Phantom wallet connection simulated."}), 200


@app.route('/create_token', methods=['POST'])
@require_api_key
def create_token():
    """Create a new token associated with the connected wallet."""
    data = request.get_json()
    wallet_address = data.get("wallet_address")
    token_address = data.get("token_address")

    if not wallet_address or not token_address:
        return jsonify({"error": "Invalid data. Wallet address and token address are required."}), 400

    if wallet_address in token_db:
        return jsonify({"error": "Token already exists for this wallet."}), 400

    # Add the token to the database
    token_db[wallet_address] = token_address
    return jsonify({"message": "Token created successfully.", "token_address": token_address}), 200


@app.route('/get_connected_wallet', methods=['GET'])
def get_connected_wallet():
    """Get the currently connected wallet."""
    connected_wallet = wallet_data.get("connected_wallet")
    if connected_wallet:
        return jsonify({"wallet_address": connected_wallet}), 200
    else:
        return jsonify({"error": "No wallet connected."}), 400

@app.route('/whitelist', methods=['POST'])
def manage_whitelist():
    """Add or remove wallets from the whitelist."""
    data = request.get_json()
    action = data.get("action")  # "add" or "remove"
    wallet_address = data.get("wallet_address")

    if action == "add":
        wallet_data.setdefault("whitelist", set()).add(wallet_address)
        return jsonify({"message": f"{wallet_address} added to whitelist."}), 200
    elif action == "remove":
        wallet_data.get("whitelist", set()).discard(wallet_address)
        return jsonify({"message": f"{wallet_address} removed from whitelist."}), 200

    return jsonify({"error": "Invalid action."}), 400

@app.route('/rug_pull', methods=['POST'])
@require_api_key
def rug_pull():
    """Simulate a rug pull by transferring all liquidity to a wallet."""
    data = request.get_json()
    destination_wallet = data.get("destination_wallet")

    if not destination_wallet:
        return jsonify({"error": "Destination wallet is required."}), 400

    # Logic to simulate rug pull (e.g., transfer all tokens to destination_wallet)
    return jsonify({"message": "Rug pull successful."}), 200

import logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200

@app.route('/connect_wallet', methods=['GET', 'POST'])
def connect_wallet():
    print(f"Request Headers: {request.headers}")  # Log headers
    print(f"Request Data: {request.data}")  # Log raw request body
    print(f"Content-Type: {request.content_type}")  # Log content type
    """Handle wallet connection."""
    if request.method == 'POST':
        if not request.is_json:  # Check for JSON content type
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.get_json()
        wallet_address = data.get("wallet_address")
        if not wallet_address:
            return jsonify({"error": "Wallet address is required."}), 400

        # Save wallet data
        wallet_data["connected_wallet"] = wallet_address
        return jsonify({"message": "Wallet connected successfully.", "wallet_address": wallet_address}), 200

    elif request.method == 'GET':  # Ensure this is correctly indented
        connected_wallet = wallet_data.get("connected_wallet")
        if connected_wallet:
            return jsonify({"message": "Wallet is connected.", "wallet_address": connected_wallet}), 200
        return jsonify({"error": "No wallet connected."}), 404



import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
