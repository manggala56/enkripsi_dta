import math
import random

def is_prime_miller_rabin(n, k=8):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=256):
    while True:
        candidate = random.getrandbits(bits)
        # Pastikan MSB dan LSB = 1 agar panjang bit tepat dan bilangan ganjil
        candidate |= (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate):
            return candidate

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Invers modular tidak ditemukan.")
    return (x % phi + phi) % phi

def generate_keypair(bits=256):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
            
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(data_bytes: bytes, pub_key: tuple) -> int:
    e, n = pub_key
    m_int = int.from_bytes(data_bytes, byteorder="big")
    if m_int >= n:
        raise ValueError("Ukuran data melebihi modulus RSA (n).")
    return pow(m_int, e, n)

def decrypt(cipher_int: int, priv_key: tuple, byte_length: int = 32) -> bytes:
    d, n = priv_key
    m_int = pow(cipher_int, d, n)
    return m_int.to_bytes(byte_length, byteorder="big")