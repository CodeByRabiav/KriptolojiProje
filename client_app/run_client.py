from flask import Flask, render_template, request, jsonify, make_response
import requests
import base64
import secrets
import random
import math
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from crypto_strategies import (
    AESLibraryStrategy, DESLibraryStrategy, RSALibraryStrategy,
    AESManualStrategy, DESManualStrategy,
    CaesarStrategy, SubstitutionStrategy, VigenereStrategy,
    AffineStrategy, PlayfairStrategy, PolybiusStrategy,
    RailFenceStrategy, RouteStrategy, ColumnarStrategy,
    HillCipherStrategy, OneTimePadStrategy, PigpenStrategy
)

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

SERVER_URL = "http://127.0.0.1:5001"


strategies = {
    
    "aes": AESLibraryStrategy(),
    "des": DESLibraryStrategy(),
    "rsa": RSALibraryStrategy(),

   
    "aes_manual": AESManualStrategy(),
    "des_manual": DESManualStrategy(),
   

    "caesar": CaesarStrategy(),
    "substitution": SubstitutionStrategy(),
    "vigenere": VigenereStrategy(),
    "affine": AffineStrategy(),
    "playfair": PlayfairStrategy(),
    "polybius": PolybiusStrategy(),
    "railfence": RailFenceStrategy(),
    "route": RouteStrategy(),
    "columnar": ColumnarStrategy(),
    "hill": HillCipherStrategy(),
    "otp": OneTimePadStrategy(),
    "pigpen": PigpenStrategy()
}


def generate_caesar_key():
    return str(random.randint(1, 25))


def generate_vigenere_key(length=5):
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for _ in range(length))


def generate_substitution_key():
    letters = list(string.ascii_uppercase)
    random.shuffle(letters)
    return ''.join(letters)


def generate_hill_key():
    while True:
        a, b, c, d = [random.randint(1, 25) for _ in range(4)]
        det = (a * d - b * c) % 26
        if det != 0 and math.gcd(det, 26) == 1:
            return f"{a},{b},{c},{d}"


@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.json
        method = data.get("method", "").lower()
        message = data.get("message", "")
        key = data.get("key", "")

        print("GELEN METHOD:", method)

        if method not in strategies:
            return jsonify({"error": f"Bilinmeyen yöntem: {method}"}), 400

      
        if not key.strip():

            if method == "caesar":
                key = generate_caesar_key()

            elif method == "vigenere":
                key = generate_vigenere_key()

            elif method == "substitution":
                key = generate_substitution_key()

            elif method == "hill":
                key = generate_hill_key()

            else:
              
                alphabet = string.ascii_letters + string.digits
                key = ''.join(secrets.choice(alphabet) for _ in range(16))

       
        strategy = strategies[method]
        encrypted_msg = strategy.encrypt(message, key)

       
        pub_key_resp = requests.get(f"{SERVER_URL}/get_public_key")
        if pub_key_resp.status_code != 200:
            return jsonify({"error": "Public key alınamadı"}), 500

        server_public_key = RSA.import_key(pub_key_resp.json()["public_key"])
        rsa_cipher = PKCS1_OAEP.new(server_public_key)

        encrypted_key_rsa = base64.b64encode(
            rsa_cipher.encrypt(key.encode())
        ).decode()

        payload = {
            "method": method,
            "encrypted_message": encrypted_msg,
            "encrypted_key": encrypted_key_rsa
        }

     
        server_resp = requests.post(
            f"{SERVER_URL}/decrypt_message",
            json=payload
        )

        if server_resp.status_code != 200:
            return jsonify({"error": f"Sunucu çözemedi: {server_resp.text}"}), 500

        return jsonify({
            "status": "success",
            "method": method,
            "encrypted_message": encrypted_msg,
            "encrypted_key_rsa": encrypted_key_rsa,
            "used_key": key
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/fetch_key', methods=['GET'])
def fetch_key():
    try:
        resp = requests.get(f"{SERVER_URL}/get_public_key")
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)
