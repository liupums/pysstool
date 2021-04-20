# https://www.pycryptodome.org/en/latest/src/examples.html
# please install the pycryptodomex, SHA256 does not exist in pycrypto
#   python3 -m pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
# RSA
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256

def testAesGcm(plaintext):
    # AES256 SymKey 
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open("encrypted.bin", "wb") as file_out:
        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]

    with open("encrypted.bin", "rb") as file_in:
        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
        # let's assume that the key is somehow available again
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        newdata = cipher.decrypt_and_verify(ciphertext, tag)
        print("plaintext '%s', decrypted data '%s'" % (plaintext.decode('utf-8'), newdata.decode('utf-8')))

def createRSAKeyPair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("privatekey.pem", "wb") as file_out:
        file_out.write(private_key)
    
    public_key = key.publickey().export_key()
    with open("publickey.pem", "wb") as file_out:
        file_out.write(public_key)
    
def testEncrypt(plaintext):
    with open("encrypted_data.bin", "wb") as file_out:
        public_key = RSA.import_key(open("publickey.pem").read())
        session_key = get_random_bytes(32)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256, label='APSP'.encode('utf-8'))
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

def testDecrypt():
    with open("encrypted_data.bin", "rb") as file_in:
        private_key = RSA.import_key(open("privatekey.pem").read())
        enc_session_key, nonce, tag, ciphertext = [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256, label='APSP'.encode('utf-8'))
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print("decrypted message '%s'" % data.decode("utf-8"))

data = "HelloWorld".encode("utf-8")
testAesGcm(data)

createRSAKeyPair()
testEncrypt(data)
testDecrypt()

