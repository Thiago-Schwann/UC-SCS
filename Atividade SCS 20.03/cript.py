from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import os

# 1. Criptografia Simétrica (AES)
def aes_encrypt_decrypt():
    key = os.urandom(16)  # Gera uma chave de 16 bytes
    cipher = AES.new(key, AES.MODE_EAX)
    plaintext = b"Mensagem Secreta"
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Decriptação
    cipher_dec = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted = cipher_dec.decrypt(ciphertext)
    return ciphertext, decrypted

# 2. Criptografia Assimétrica (RSA)
def rsa_encrypt_decrypt():
    key = RSA.generate(2048)
    public_key = key.publickey()
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    plaintext = b"Mensagem Secreta"
    ciphertext = cipher_rsa.encrypt(plaintext)
    
    cipher_rsa_dec = PKCS1_OAEP.new(key)
    decrypted = cipher_rsa_dec.decrypt(ciphertext)
    return ciphertext, decrypted

# 3. Função Hash (SHA-256)
def hash_function():
    plaintext = "Mensagem Secreta"
    hashed = hashlib.sha256(plaintext.encode()).hexdigest()
    return hashed

# Testando os algoritmos
aes_result = aes_encrypt_decrypt()
rsa_result = rsa_encrypt_decrypt()
hash_result = hash_function()

# Exibir os resultados
print("AES - Criptografado:", aes_result[0])
print("AES - Decriptado:", aes_result[1])
print("RSA - Criptografado:", rsa_result[0])
print("RSA - Decriptado:", rsa_result[1])
print("Hash SHA-256:", hash_result)
