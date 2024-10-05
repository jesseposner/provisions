"""
This module defines the constants for the elliptic curve secp256k1,
which is widely used in cryptographic applications like Bitcoin.
The curve operates over a finite field of prime order `P`, with a
base point `G` of order `N`, specified by its coordinates `Gx` and `Gy`.
"""

# The prime modulus of the finite field
P: int = 2**256 - 2**32 - 977

# The order of the base point G
N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The curve coefficients (secp256k1 is y^2 = x^3 + ax + b,
# with a = 0 and b = 7)
A: int = 0
B: int = 7

# X-coordinate of the generator point G
Gx: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798

# Y-coordinate of the generator point G
Gy: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
