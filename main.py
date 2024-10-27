from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import jwt
import time
import sqlite3

# Configuration
DATABASE = 'totally_not_my_privateKeys.db'

# Database functions
def connect_to_db():
    return sqlite3.connect(DATABASE)

def create_table():
    with connect_to_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,  -- Store as TEXT (PEM string)
                exp INTEGER NOT NULL
            )
        ''')
        conn.commit()


def generate_and_store_key(expiry):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    with connect_to_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_private_key, expiry))
        conn.commit()
        return cursor.lastrowid

def setup_keys():
    now = int(time.time())
    with connect_to_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")
    generate_and_store_key(expiry=now - 10)  # Expired key
    generate_and_store_key(expiry=now + 3600)  # Valid key

def retrieve_key(expired=False):
    now = int(time.time())
    query = "SELECT key, kid FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
    params = (now,)

    if expired:
        query = "SELECT key, kid FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
        params = (now,)

    with connect_to_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        key_row = cursor.fetchone()
        
    if key_row is None:
        raise Exception("No matching key found")

    # Convert PEM string back to private key object
    pem_private_key = key_row[0].encode('utf-8')
    kid = key_row[1]  # Assuming kid is stored as a separate column
    return serialization.load_pem_private_key(pem_private_key, password=None, backend=default_backend()), kid

def sign_jwt(payload, private_key, kid):
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def get_valid_keys():
    now = int(time.time())
    valid_keys = []
    with connect_to_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
        rows = cursor.fetchall()
        for kid, pem_key in rows:
            private_key = serialization.load_pem_private_key(pem_key.encode('utf-8'), password=None)
            numbers = private_key.public_key().public_numbers()
            valid_keys.append({
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(numbers.n),
                "e": int_to_base64(numbers.e),
            })
    return valid_keys

def create_app():
    app = Flask(__name__)

    @app.route('/auth', methods=['POST'])
    @app.route('/auth', methods=['POST'])
    def auth():
        try:
            expired = request.args.get('expired', 'false').lower() == 'true'
            private_key, kid = retrieve_key(expired=expired)

            payload = {"user": "username", "exp": int(time.time()) + 3600}
            # Ensure kid is in string format
            token = sign_jwt(payload, private_key, str(kid))

            return jsonify({"token": token}), 200  # Return token in the response
        except Exception as e:
            return jsonify({"error": str(e)}), 400



    @app.route('/.well-known/jwks.json', methods=['GET'])
    def jwks():
        valid_keys = get_valid_keys()
        if valid_keys:
            return jsonify({"keys": valid_keys}), 200
        return jsonify({"error": "No valid keys found."}), 404

    return app

# Main execution
if __name__ == '__main__':
    create_table()
    setup_keys()
    app = create_app()
    app.run(debug=True, host="localhost", port=8080)
