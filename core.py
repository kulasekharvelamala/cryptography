def encrypt_and_hide(carrier_path, secret_key, message, method, out_path):
    if method not in ENCRYPTION_METHODS:
        raise ValueError("Unsupported encryption method")

    enc = ENCRYPTION_METHODS[method]
    ciphertext = enc.encrypt(message.encode(), secret_key.encode())
    payload = build_payload(ciphertext, method)

    ctype, cpath = detect_carrier_type(carrier_path)
    if ctype == "image":
        return hide_in_image(cpath, payload, out_path)
    elif ctype == "wav":
        return hide_in_wav(cpath, payload, out_path)
    elif ctype == "video":
        return hide_in_video(cpath, payload, out_path)
    else:
        raise ValueError("Unsupported carrier type")


def extract_and_decrypt(stego_path, secret_key):
    ctype, cpath = detect_carrier_type(stego_path)
    if ctype == "image":
        bits = extract_from_image(cpath)
    elif ctype == "wav":
        bits = extract_from_wav(cpath)
    elif ctype == "video":
        bits = extract_from_video(cpath)
    else:
        raise ValueError("Unsupported carrier type")

    message_bytes, method = parse_payload_from_bits(bits)
    enc = ENCRYPTION_METHODS[method]
    plaintext = enc.decrypt(message_bytes, secret_key.encode())
    return plaintext.decode(errors="ignore"), method
