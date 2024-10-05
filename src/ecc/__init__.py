"""
The `ecc` package provides elliptic curve cryptography primitives,
specifically tailored for the secp256k1 curve used in Bitcoin and
other cryptographic applications.

This package includes:

- `Point`: A class representing points on the elliptic curve.
- `G`: The generator point for secp256k1.
- Curve constants like `P`, `N`, `A`, `B`.

By importing the `ecc` package, you have direct access to these
classes and constants for performing elliptic curve operations.
"""

from .constants import (
    P,
    N,
    A,
    B,
    Gx,
    Gy,
)

from .point import Point, G

__all__ = [
    "P",
    "N",
    "A",
    "B",
    "Gx",
    "Gy",
    "Point",
    "G",
]
