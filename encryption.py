import base64
import os
import rsa_engine
import chacha20_engine

def encrypt_message(plaintext: str, recipient_public_key: tuple) -> dict:
    plaintext_bytes = plaintext.encode("utf-8")
    
    session_key = os.urandom(32)
    nonce = os.urandom(12)
    
    # Enkripsi plaintext 
    ciphertext_bytes = chacha20_engine.process_stream(plaintext_bytes, session_key, nonce)
    
    #  Kunci session key dienkripsi 
    enc_session_key_int = rsa_engine.encrypt(session_key, recipient_public_key)
    
    # payload
    payload = {
        "enc_session_key": hex(enc_session_key_int),
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext_bytes).decode("utf-8")
    }
    return payload