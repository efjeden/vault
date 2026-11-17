from ykman.device import list_all_devices
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import YubiOtpSession, SLOT

def hmac_response(challenge: bytes, slot=SLOT.TWO) -> bytes:
    """Odpowiedz klucza sprzetowego. 20 B."""
    if not 1 <= len(challenge) <= 63:
        raise ValueError("challenge musi miec 1-63 B (przy 64 klucz odbiega od HMAC-SHA1)")
    dev, _ = list_all_devices()[0]
    with dev.open_connection(OtpConnection) as conn:
        return YubiOtpSession(conn).calculate_hmac_sha1(slot, challenge)
    