from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import json
import jwt
import time
import sqlite3

hostName = "localhost"
serverPort = 8080
DATABASE = 'totally_not_my_privateKeys.db'

def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def generate_and_store_key(expiry):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO keys (key, exp) VALUES (?, ?)
        """, (pem_private_key, expiry))
        conn.commit()

def setup_keys():
    now = int(time.time())
    generate_and_store_key(expiry=now - 10)  # Expired key
    generate_and_store_key(expiry=now + 3600)  # Valid key

create_table()
setup_keys()

def sign_jwt(payload, secret, algorithm="HS256"):
    return jwt.encode(payload, secret, algorithm=algorithm)

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/auth":
            expired = "expired" in self.path
            if expired:
                token = sign_jwt({"user": "username", "exp": int(time.time()) - 1}, "secret")
            else:
                token = sign_jwt({"user": "username", "exp": int(time.time()) + 3600}, "secret")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(token, "utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            valid_keys = self.get_valid_keys()
            if valid_keys:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"keys": valid_keys}), "utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No valid keys found.")
            return

        self.send_response(405)
        self.end_headers()

    def get_valid_keys(self):
        now = int(time.time())
        valid_keys = []

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, exp FROM keys WHERE exp > ?", (now,))
            rows = cursor.fetchall()

            for pem_key, exp in rows:
                if isinstance(pem_key, str):
                    pem_key = pem_key.encode('utf-8')
                private_key = serialization.load_pem_private_key(pem_key, password=None)
                numbers = private_key.public_key().public_numbers()
                valid_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(exp),
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

        return valid_keys

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")
