from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

from crypto_strategies import (
    AESLibraryStrategy, DESLibraryStrategy, RSALibraryStrategy,
    AESManualStrategy, DESManualStrategy,
    CaesarStrategy, SubstitutionStrategy, VigenereStrategy,
    AffineStrategy, PlayfairStrategy, PolybiusStrategy,
    RailFenceStrategy, RouteStrategy, ColumnarStrategy,
    HillCipherStrategy, OneTimePadStrategy, PigpenStrategy
)

app = Flask(__name__)


rsa_key = RSA.generate(2048)


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

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    return jsonify({
        "public_key": rsa_key.publickey().export_key().decode()
    })

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        method = data.get("method", "").lower()
        enc_msg = data.get("encrypted_message")
        enc_key = data.get("encrypted_key")

        print(f"\n--- YENİ MESAJ ({method}) ---")

        if method not in strategies:
            return jsonify({"error": f"Bilinmeyen yöntem: {method}"}), 400

        strategy = strategies[method]

        
        if method not in ["rsa_manual"]:
            if not enc_key:
                return jsonify({"error": "Encrypted key eksik"}), 400

            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            sym_key = cipher_rsa.decrypt(
                base64.b64decode(enc_key)
            ).decode()

            print(f"Çözülen Simetrik Anahtar: {sym_key}")
        else:
            sym_key = None

      
        decrypted_msg = strategy.decrypt(enc_msg, sym_key)

        print(f"Çözülen Mesaj: {decrypted_msg}\n")

        return jsonify({
            "status": "success",
            "decrypted_message": decrypted_msg
        })

    except Exception as e:
        print("SUNUCU HATASI:", e)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5001, debug=True)
