from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from crypto_strategies import (
    AESLibraryStrategy, DESLibraryStrategy, RSALibraryStrategy,
    CaesarStrategy, SubstitutionStrategy, VigenereStrategy,
    AffineStrategy, PlayfairStrategy, PolybiusStrategy,
    RailFenceStrategy, RouteStrategy, ColumnarStrategy,
    HillCipherStrategy, OneTimePadStrategy, PigpenStrategy,
    AESManualStrategy
)

app = Flask(__name__)


rsa_key = RSA.generate(2048)


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

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    return jsonify({"public_key": rsa_key.publickey().export_key().decode()})

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        enc_msg = data.get('encrypted_message')
        enc_key = data.get('encrypted_key')    
        method = data.get('method')
        
        print(f"\n--- YENİ MESAJ GELDİ ({method}) ---")

        
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
      
        decrypted_sym_key_bytes = cipher_rsa.decrypt(base64.b64decode(enc_key))
        decrypted_sym_key = decrypted_sym_key_bytes.decode('utf-8')
        
        print(f"Çözülmüş Simetrik Anahtar: {decrypted_sym_key}")

       
        strategy = strategies.get(method)
        if not strategy:
            return jsonify({"error": "Bilinmeyen yöntem"}), 400

        
        decrypted_msg = strategy.decrypt(enc_msg, decrypted_sym_key)
        
        print(f"Çözülmüş Mesaj: {decrypted_msg}\n")
        
        return jsonify({
            "status": "Success", 
            "decrypted_message": decrypted_msg
        })

    except Exception as e:
        print(f"SUNUCU HATASI: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
   
    app.run(port=5001, debug=True)