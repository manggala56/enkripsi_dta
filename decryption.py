import base64
import rsa_engine
import chacha20_engine

def decrypt_message(payload: dict, recipient_private_key: tuple) -> str:
    enc_session_key_int = int(payload["enc_session_key"], 16)
    nonce = base64.b64decode(payload["nonce_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    
    # 1. Dekripsi session 
    session_key = rsa_engine.decrypt(enc_session_key_int, recipient_private_key, byte_length=32)
    
    # 2. Dekripsi ciphertext
    decrypted_bytes = chacha20_engine.process_stream(ciphertext, session_key, nonce)
    
    return decrypted_bytes.decode("utf-8")