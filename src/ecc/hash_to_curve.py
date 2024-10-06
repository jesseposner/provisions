import hashlib
from math import ceil


class HashToCurve:
    @classmethod
    def expand_message_xmd(
        cls, msg: bytes, DST: bytes, len_in_bytes: int
    ) -> bytes:
        """
        Implements expand_message_xmd as specified in RFC 9380, Section 5.3.1.

        :param msg: The input message to hash (bytes).
        :param DST: The domain separation tag (bytes).
        :param len_in_bytes: The length of the requested output in bytes.
        :return: A byte string of length len_in_bytes.
        """

        b_in_bytes = hashlib.sha256().digest_size
        r_in_bytes = hashlib.sha256().block_size
        ell = ceil(len_in_bytes / b_in_bytes)
        if ell > 255:
            raise ValueError("Ell is too large")
        DST_prime = DST + len(DST).to_bytes(1, "big")
        Z_pad = bytes(r_in_bytes)
        l_i_b_str = len_in_bytes.to_bytes(2, "big")
        msg_prime = Z_pad + msg + l_i_b_str + b"\x00" + DST_prime
        b_0 = hashlib.sha256(msg_prime).digest()
        b_vals = []
        b_vals.append(hashlib.sha256(b_0 + b"\x01" + DST_prime).digest())
        for i in range(1, ell):
            tmp = bytes(x ^ y for x, y in zip(b_0, b_vals[i - 1]))
            b_i = hashlib.sha256(
                tmp + (i + 1).to_bytes(1, "big") + DST_prime
            ).digest()
            b_vals.append(b_i)
        uniform_bytes = b"".join(b_vals)
        return uniform_bytes[:len_in_bytes]
