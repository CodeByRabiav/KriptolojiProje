from flask import Flask, render_template, request, jsonify, make_response
import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from crypto_strategies import (
    AESLibraryStrategy, DESLibraryStrategy, RSALibraryStrategy,
    CaesarStrategy, SubstitutionStrategy, VigenereStrategy,
    AffineStrategy, PlayfairStrategy, PolybiusStrategy,
    RailFenceStrategy, RouteStrategy, ColumnarStrategy,
    HillCipherStrategy, OneTimePadStrategy, PigpenStrategy,
    AESManualStrategy
)


app = Flask(__name__)


app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

SERVER_URL = "http://127.0.0.1:5001"


strategies = {
   "AES": AESLibraryStrategy(),
    "DES": DESLibraryStrategy(),
    "RSA": RSALibraryStrategy(),
    "Caesar": CaesarStrategy(),
    "Substitution": SubstitutionStrategy(),
    "Vigenere": VigenereStrategy(),
    "Affine": AffineStrategy(),
    "Playfair": PlayfairStrategy(),
    "Polybius": PolybiusStrategy(),
    "RailFence": RailFenceStrategy(),
    "Route": RouteStrategy(),
    "Columnar": ColumnarStrategy(),
    "Hill": HillCipherStrategy(),
    "OneTimePad": OneTimePadStrategy(),
    "Pigpen": PigpenStrategy(),
    "AES_Manual": AESManualStrategy()
}

@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/process', methods=['POST'])
def process():
    try:
        
        data = request.json
        method = data.get('method')
        msg = data.get('message')
        key = data.get('key')

        print(f"İşlem Başladı: {method} ile '{msg}' şifreleniyor...")

        
        strategy = strategies.get(method)
        if not strategy:
            return jsonify({"error": "Geçersiz Yöntem"}), 400
        
        
        encrypted_msg = strategy.encrypt(msg, key)

        
        pub_key_resp = requests.get(f"{SERVER_URL}/get_public_key")
        if pub_key_resp.status_code != 200:
            return jsonify({"error": "Sunucudan Public Key alınamadı"}), 500
            
        server_public_key = RSA.import_key(pub_key_resp.json()['public_key'])
        rsa_cipher = PKCS1_OAEP.new(server_public_key)
        
       
        encrypted_key_rsa = base64.b64encode(rsa_cipher.encrypt(key.encode())).decode()

       
        payload = {
            "method": method,
            "encrypted_message": encrypted_msg,
            "encrypted_key": encrypted_key_rsa 
        }
        
        
        server_resp = requests.post(f"{SERVER_URL}/decrypt_message", json=payload)
        
        if server_resp.status_code != 200:
             return jsonify({"error": f"Sunucu çözemedi: {server_resp.text}"}), 500

       
        return jsonify({
            "status": "Success",
            "encrypted_message": encrypted_msg,
            "encrypted_key_rsa": encrypted_key_rsa
        })

    except Exception as e:
        print(f"HATA: {e}")
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