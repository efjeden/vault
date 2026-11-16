from dataclasses import dataclass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEK_LEN = 32
INFO_KEK = b"sejf-v1/kek"

@dataclass
class SlotMeta:
    """Czytane z naglowka pliku - jawne, ale objete uwierzytelnieniem."""
    kdf_salt: bytes      # 16 B
    argon_m: int         # w KiB: 2 GiB = 2097152
    argon_t: int
    argon_p: int
    challenge: bytes     # 32 B
    source: str          # "hmac-sha1" | "hmac-secret" | "password-only"

def stretch_password(password: str, meta: SlotMeta) -> bytes:
    """Wolno, bo haslo ma niska entropie. 32 B."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=meta.kdf_salt,
        time_cost=meta.argon_t,
        memory_cost=meta.argon_m,
        parallelism=meta.argon_p,
        hash_len=32,
        type=Type.ID,
    )

def _join(*parts: bytes) -> bytes:
    """Prefiksy dlugosci - bez nich ('ab','cd') i ('abc','d') daja to samo."""
    out = b""
    for p in parts:
        if len(p) > 255:
            raise ValueError("czesc dluzsza niz 255 B")
        out += bytes([len(p)]) + p
    return out

def derive_kek(password: str, response: bytes, meta: SlotMeta) -> bytes:
    """Laczy oba sekrety w klucz opakowujacy. 32 B."""
    k_pw = stretch_password(password, meta)
    ikm = _join(k_pw, response)          # szybko: oba wejscia maja juz pelna entropie
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEK_LEN,
        salt=meta.kdf_salt,
        info=INFO_KEK,                   # separacja domen
    ).derive(ikm)