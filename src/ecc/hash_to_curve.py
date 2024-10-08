import hashlib
from typing import Tuple, List
from math import ceil
from .constants import P, Z
from .point import Point


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

    @classmethod
    def hash_to_field(cls, msg: bytes, count: int, DST: bytes) -> List[int]:
        """
        Hashes the message msg to count elements in the field F_p.

        :param msg: Byte string to hash.
        :param count: Number of field elements to output.
        :param DST: Domain Separation Tag.
        :return: List of field elements [u_0, ..., u_{count - 1}]
        """

        L = 48
        len_in_bytes = count * L

        uniform_bytes = cls.expand_message_xmd(msg, DST, len_in_bytes)

        u = []
        for i in range(count):
            elm_offset = L * i
            tv = uniform_bytes[elm_offset : elm_offset + L]
            e_i = int.from_bytes(tv, "big") % P
            u.append(e_i)
        return u

    @classmethod
    def sqrt_ratio_3mod4(cls, u: int, v: int) -> Tuple[bool, int]:
        """
        Compute sqrt(u / v) when p % 4 == 3.

        :param u: Numerator in F_p
        :param v: Denominator in F_p (v != 0)
        :return: Tuple (isQR, y), where isQR indicates if u/v is a square,
                 and y is sqrt(u/v) or sqrt(Z * u/v)
        """
        if v % P == 0:
            raise ZeroDivisionError("Denominator v must not be zero")

        c1 = (P - 3) // 4
        c2 = pow(-Z, (P + 1) // 4, P)

        # 1. tv1 = v^2
        tv1 = pow(v, 2, P)

        # 2. tv2 = u * v
        tv2 = (u * v) % P

        # 3. tv1 = tv1 * tv2
        tv1 = (tv1 * tv2) % P

        # 4. y1 = tv1^c1
        y1 = pow(tv1, c1, P)

        # 5. y1 = y1 * tv2
        y1 = (y1 * tv2) % P

        # 6. y2 = y1 * c2
        y2 = (y1 * c2) % P

        # 7. tv3 = y1^2
        tv3 = pow(y1, 2, P)

        # 8. tv3 = tv3 * v
        tv3 = (tv3 * v) % P

        # 9. isQR = tv3 == u
        isQR = tv3 == (u % P)

        # 10. y = CMOV(y2, y1, isQR)
        y = y1 if isQR else y2

        # 11. return (isQR, y)
        return (isQR, y)

    @classmethod
    def map_to_curve_simple_swu(cls, u: int) -> Tuple[int, int]:
        """
        Simplified SWU map for AB != 0, mapping to the isogenous curve E'.

        :param u: An element of the field F_p.
        :return: A point (x, y) on the isogenous curve E'.
        """

        A = 0x3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533
        B = 1771

        # 1.  tv1 = u^2
        tv1 = pow(u, 2, P)

        # 2.  tv1 = Z * tv1
        tv1 = (Z * tv1) % P

        # 3.  tv2 = tv1^2
        tv2 = pow(tv1, 2, P)

        # 4.  tv2 = tv2 + tv1
        tv2 = (tv2 + tv1) % P

        # 5.  tv3 = tv2 + 1
        tv3 = (tv2 + 1) % P

        # 6.  tv3 = B * tv3
        tv3 = (B * tv3) % P

        # 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
        tv4 = -tv2 % P if tv2 != 0 else Z % P

        # 8.  tv4 = A * tv4
        tv4 = (A * tv4) % P

        # 9.  tv2 = tv3^2
        tv2 = pow(tv3, 2, P)

        # 10. tv6 = tv4^2
        tv6 = pow(tv4, 2, P)

        # 11. tv5 = A * tv6
        tv5 = (A * tv6) % P

        # 12. tv2 = tv2 + tv5
        tv2 = (tv2 + tv5) % P

        # 13. tv2 = tv2 * tv3
        tv2 = (tv2 * tv3) % P

        # 14. tv6 = tv6 * tv4
        tv6 = (tv6 * tv4) % P

        # 15. tv5 = B * tv6
        tv5 = (B * tv6) % P

        # 16. tv2 = tv2 + tv5
        tv2 = (tv2 + tv5) % P

        # 17.   x = tv1 * tv3
        x = (tv1 * tv3) % P

        # 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
        is_gx1_square, y1 = cls.sqrt_ratio_3mod4(tv2, tv6)

        # 19.   y = tv1 * u
        y = (tv1 * u) % P

        # 20.   y = y * y1
        y = (y * y1) % P

        # 21.   x = CMOV(x, tv3, is_gx1_square)
        x = tv3 if is_gx1_square else x

        # 22.   y = CMOV(y, y1, is_gx1_square)
        y = y1 if is_gx1_square else y

        # 23.  e1 = sgn0(u) == sgn0(y)
        e1 = u % 2 == y % 2

        # 24.   y = CMOV(-y, y, e1)
        y = y if e1 else -y % P

        # 25.   x = x / tv4
        x = (x * pow(tv4, P - 2, P)) % P

        # 26. return (x, y)
        return (x, y)

    @classmethod
    def iso_map(cls, x_prime: int, y_prime: int) -> Tuple[int, int]:
        """
        Maps a point from the isogenous curve E' to the curve E using the
        3-isogeny map (see RFC9380 E.1).

        :param x_prime: x-coordinate of the point on E'.
        :param y_prime: y-coordinate of the point on E'.
        :return: A point (x, y) on the curve E.
        """

        # Constants for x_num
        k_1_0 = (
            0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7
        )
        k_1_1 = (
            0x7D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581
        )
        k_1_2 = (
            0x534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262
        )
        k_1_3 = (
            0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C
        )

        # Constants for x_den
        k_2_0 = (
            0xD35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B
        )
        k_2_1 = (
            0xEDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14
        )

        # Constants for y_num
        k_3_0 = (
            0x4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C
        )
        k_3_1 = (
            0xC75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3
        )
        k_3_2 = (
            0x29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931
        )
        k_3_3 = (
            0x2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84
        )

        # Constants for y_den
        k_4_0 = (
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B
        )
        k_4_1 = (
            0x7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573
        )
        k_4_2 = (
            0x6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F
        )

        # Compute powers of x'
        x_prime2 = pow(x_prime, 2, P)
        x_prime3 = pow(x_prime, 3, P)

        # Compute x_num and x_den
        x_num = (
            k_1_3 * x_prime3 + k_1_2 * x_prime2 + k_1_1 * x_prime + k_1_0
        ) % P
        x_den = (x_prime2 + k_2_1 * x_prime + k_2_0) % P

        # Compute x
        if x_den == 0:
            raise ValueError("Invalid x_den value")
        x_den_inv = pow(x_den, P - 2, P)
        x = (x_num * x_den_inv) % P

        # Compute y_num and y_den
        y_num = (
            k_3_3 * x_prime3 + k_3_2 * x_prime2 + k_3_1 * x_prime + k_3_0
        ) % P
        y_den = (x_prime3 + k_4_2 * x_prime2 + k_4_1 * x_prime + k_4_0) % P

        # Compute y
        if y_den == 0:
            raise ValueError("Invalid y_den value")
        y_den_inv = pow(y_den, P - 2, P)
        y = (y_prime * y_num * y_den_inv) % P

        return (x, y)

    @classmethod
    def hash_to_curve(cls, msg: bytes, DST: bytes) -> Point:
        """
        Hashes a message to a point on the secp256k1 curve.

        :param msg: Byte string to hash.
        :param DST: Domain Separation Tag.
        :return: Tuple (x, y) representing a point on secp256k1.
        """

        # 1. u = hash_to_field(msg, 2)
        u = cls.hash_to_field(msg, 2, DST)
        # 2. Q0' = map_to_curve(u[0])
        Q0_prime = cls.map_to_curve_simple_swu(u[0])
        # 3. Q0 = iso_map(Q0')
        Q0 = cls.iso_map(*Q0_prime)
        # 4. Q1' = map_to_curve(u[1])
        Q1_prime = cls.map_to_curve_simple_swu(u[1])
        # 5. Q1 = iso_map(Q1')
        Q1 = cls.iso_map(*Q1_prime)
        # 6. R = Q0 + Q1
        R = Point(*Q0) + Point(*Q1)
        # 7. return R
        return R
