from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_HEX = "43e4da7ae648e1621a000ec7c468edb9"  #klucz
PRIVATE_ID_HEX = "377639b9c631"                   
MODHEX = "cbdefghijklnrtuv"


def modhex_to_bytes(s:str) -> bytes:
    pozycje = [MODHEX.index(c) for c in s.lower()]
    return bytes((pozycje[i] << 4) | pozycje[i + 1] for i in range(0, len(pozycje), 2))


def crc16(data: bytes) -> int:
    crc = 0xFFFF #same 1
    for b in data:
        crc ^= b #xorowanie
        for _ in range(8):
            lsb = crc & 1 #najnizszy bit
            crc >>= 1 #przesuwamy reszte o 1 w prawo
            if lsb: #jesli rowny 1 to mieszamy wynik ze stala
                crc ^= 0x8408
    return crc


def decrypt_otp(token: str, key: bytes) -> dict:
    token = token.strip()
    assert len(token) == 44
    public_id = token[:12]
    cipher_block = modhex_to_bytes(token[12:])  #zamiana na 16 bajtow 32 liter

    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    p = dec.update(cipher_block) + dec.finalize()

    return {
        "public_id": public_id,
        "private_id": p[0:6].hex(),
        "use_counter": int.from_bytes(p[6:8], "little"),
        "timestamp": int.from_bytes(p[8:11], "little"),  
        "session_counter": p[11],
        "random": p[12:14].hex(),
        "crc_ok": crc16(p) == 0xF0B8, 
    }


if __name__ == "__main__":
    key = bytes.fromhex(AES_KEY_HEX)
    token = input("Dotknij klucza (token): ")
    r = decrypt_otp(token, key)
    print("public_id      :", r["public_id"])
    print("private_id     :", r["private_id"])
    print("use_counter    :", r["use_counter"])
    print("timestamp      :", r["timestamp"])
    print("session_counter:", r["session_counter"])
    print("random         :", r["random"])
    print("crc_ok         :", r["crc_ok"])
    print("private ID zgodny:", r["private_id"] == PRIVATE_ID_HEX)
    print("CRC poprawne     :", r["crc_ok"])