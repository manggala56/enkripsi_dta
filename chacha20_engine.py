import struct

def rot32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rot32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rot32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rot32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rot32(state[b] ^ state[c], 7)

def chacha20_block(key_bytes: bytes, counter: int, nonce_bytes: bytes) -> bytes:
    # 4 konstanta standar RFC 8439: "expand 32-byte k"
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = list(struct.unpack("<8I", key_bytes))
    nonce_words = list(struct.unpack("<3I", nonce_bytes))
    init_state = constants + key_words + [counter] + nonce_words

    state = list(init_state)
    for _ in range(10):  # 20 putaran total
        # Column round
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        # Diagonal round
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)

    keystream_block = bytearray()
    for i in range(16):
        out_word = (state[i] + init_state[i]) & 0xFFFFFFFF
        keystream_block.extend(struct.pack("<I", out_word))
    return bytes(keystream_block)

def process_stream(data: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
    output = bytearray()
    counter = initial_counter
    for i in range(0, len(data), 64):
        keystream = chacha20_block(key, counter, nonce)
        chunk = data[i:i + 64]
        for b_data, b_key in zip(chunk, keystream):
            output.append(b_data ^ b_key)
        counter += 1
    return bytes(output)