from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_file(file_path, private_key_data):
    key = RSA.import_key(private_key_data)
    with open(file_path, 'rb') as f:
        data = f.read()
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(file_path, signature, public_key_data):
    key = RSA.import_key(public_key_data)
    with open(file_path, 'rb') as f:
        data = f.read()
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
