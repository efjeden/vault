from kdf import SlotMeta, stretch_password, derive_kek
from hardware import hmac_response

meta = SlotMeta(
    kdf_salt=bytes(range(16)),   # na sztywno TYLKO do demonstracji
    argon_m=256 * 1024,          # 256 MiB - szybciej przy testach
    argon_t=3,
    argon_p=4,
    challenge=bytes(range(32)),
    source="hmac-sha1",
)

print("1. Haslo przez Argon2id ")
k_pw = stretch_password("tajne-haslo", meta)
print("   k_pw:", k_pw.hex())

print("\n2. Odpowiedz z YubiKeya...")
resp = hmac_response(meta.challenge)
print("   resp:", resp.hex(), f"({len(resp)} B)")

print("\n3. HKDF laczy oba w klucz opakowujacy...")
kek = derive_kek("tajne-haslo", resp, meta)
print("   kek: ", kek.hex(), f"({len(kek)} B)")

print("\n4. To samo haslo -> ten sam kek?")
kek2 = derive_kek("tajne-haslo", resp, meta)
print("   ", "TAK" if kek == kek2 else "NIE - cos jest zle")

print("\n5. Inne haslo -> inny kek?")
kek3 = derive_kek("zle-haslo", resp, meta)
print("   ", "TAK" if kek != kek3 else "NIE - cos jest zle")
print("   kek dla zlego hasla:", kek3.hex())