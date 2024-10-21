import secrets
from src.ecc import HashToCurve, Point, G, N


def compute_h() -> Point:
    """
    Computes the point h by hashing the string 'Provisions' to the curve using
    the appropriate DST.
    """
    DST = b"PROVISIONS-V01-CS01-with-secp256k1_XMD:SHA-256_SSWU_RO_"
    msg = b"Provisions"
    h = HashToCurve.hash_to_curve(msg, DST)
    return h


H = compute_h()


def asset_comitment(value: int, is_owned: bool) -> Point:
    """ """
    v = secrets.randbits(256) % N
    ret = v * H

    if is_owned:
        b = value * G
        ret += b

    return ret
