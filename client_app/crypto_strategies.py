import string
import math
import base64
import numpy as np
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

class CryptoStrategy:
    def encrypt(self, text, key): pass
    def decrypt(self, text, key): pass


class AESLibraryStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        cipher = AES.new(pad(key.encode().ljust(16)[:16], 16), AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(pad(text.encode(), 16))).decode()
    def decrypt(self, text, key):
        cipher = AES.new(pad(key.encode().ljust(16)[:16], 16), AES.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 16).decode()

class DESLibraryStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        cipher = DES.new(key.encode().ljust(8)[:8], DES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(pad(text.encode(), 8))).decode()
    def decrypt(self, text, key):
        cipher = DES.new(key.encode().ljust(8)[:8], DES.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 8).decode()

class RSALibraryStrategy(CryptoStrategy):
   
    def encrypt(self, text, key):
        recipient_key = RSA.import_key(key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return base64.b64encode(cipher_rsa.encrypt(text.encode())).decode()
    def decrypt(self, text, key):
        private_key = RSA.import_key(key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(base64.b64decode(text)).decode()


class CaesarStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        shift = int(key) % 26
        res = ""
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                res += chr((ord(char) - start + shift) % 26 + start)
            else: res += char
        return res
    def decrypt(self, text, key):
        return self.encrypt(text, str(26 - (int(key) % 26)))

class VigenereStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        res = []
        key = key.upper()
        for i in range(len(text)):
            if text[i].isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                start = ord('A') if text[i].isupper() else ord('a')
                res.append(chr((ord(text[i]) - start + shift) % 26 + start))
            else: res.append(text[i])
        return "".join(res)
    def decrypt(self, text, key):
        res = []
        key = key.upper()
        for i in range(len(text)):
            if text[i].isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                start = ord('A') if text[i].isupper() else ord('a')
                res.append(chr((ord(text[i]) - start - shift + 26) % 26 + start))
            else: res.append(text[i])
        return "".join(res)

class AffineStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        a, b = map(int, key.split(','))
        return "".join([chr(((a * (ord(c) - 65) + b) % 26) + 65) if c.isupper() else c for c in text.upper()])
    def decrypt(self, text, key):
        a, b = map(int, key.split(','))
        a_inv = pow(a, -1, 26)
        return "".join([chr(((a_inv * (ord(c) - 65 - b)) % 26) + 65) if c.isupper() else c for c in text.upper()])


class HillCipherStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        k = np.array(list(map(int, key.split(',')))).reshape(2, 2)
        text = text.upper().replace(" ", "")
        if len(text) % 2 != 0: text += "X"
        res = ""
        for i in range(0, len(text), 2):
            v = np.array([ord(text[i])-65, ord(text[i+1])-65])
            enc = np.dot(k, v) % 26
            res += chr(int(enc[0])+65) + chr(int(enc[1])+65)
        return res

class RailFenceStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        n = int(key)
        fence = [[] for _ in range(n)]
        rail, direction = 0, 1
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == n-1 or rail == 0: direction *= -1
        return "".join(["".join(r) for r in fence])

class SubstitutionStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        table = str.maketrans(string.ascii_uppercase, key.upper())
        return text.upper().translate(table)

class PolybiusStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        grid = "ABCDE"
        table = {c: f"{grid[i//5]}{grid[i%5]}" for i, c in enumerate("ABCDEFGHIKLMNOPQRSTUVWXYZ")}
        return " ".join([table.get(c, "??") for c in text.upper().replace("J", "I") if c.isalpha()])

class PlayfairStrategy(CryptoStrategy):
    def encrypt(self, text, key): return f"Playfair-Encrypted({text[:5]}...)"

class RouteStrategy(CryptoStrategy):
    def encrypt(self, text, key): return text[::-1]

class ColumnarStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        order = sorted(range(len(key)), key=lambda k: key[k])
        return "".join([text[i::len(key)] for i in order])

class PigpenStrategy(CryptoStrategy):
    def encrypt(self, text, key): return "-".join([hex(ord(c)) for c in text])

class OneTimePadStrategy(CryptoStrategy):
    def encrypt(self, text, key):
        return "".join([chr(ord(t) ^ ord(key[i % len(key)])) for i, t in enumerate(text)])

class AESManualStrategy(CryptoStrategy):
    def encrypt(self, text, key): return f"Manual-AES({text[:5]}...)"