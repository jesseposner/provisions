"""
This module defines the `Point` class, representing points on the secp256k1
elliptic curve. It includes methods for point arithmetic such as addition,
multiplication, and negation, as well as serialization and deserialization
of points in SEC1 compressed and x-only formats.
"""

from __future__ import annotations
from typing import Optional, Any
from .constants import P, N, A, B, Gx, Gy


class Point:
    """Class representing a point on the secp256k1 elliptic curve."""

    def __init__(self, x: Optional[int], y: Optional[int]) -> None:
        """
        Initialize a point on the elliptic curve.

        :param x: The x-coordinate of the point. None represents infinity.
        :param y: The y-coordinate of the point. None represents infinity.
        """
        self.x = x
        self.y = y

        if (self.x is None) != (self.y is None):
            raise ValueError(
                "Both x and y should be None for the point at infinity."
            )

        if self.x is not None and self.y is not None:
            if not (0 <= self.x < P and 0 <= self.y < P):
                raise ValueError(
                    "Point coordinates must be within field range."
                )
            if not self.is_on_curve():
                raise ValueError(
                    f"Point ({self.x}, {self.y}) is not on the curve."
                )

    def is_on_curve(self) -> bool:
        """
        Check if the point lies on the secp256k1 curve.

        :return: True if the point is on the curve, False otherwise.
        """
        if self.is_at_infinity():
            return True
        assert self.x is not None and self.y is not None
        lhs = self.y * self.y % P
        rhs = (self.x * self.x * self.x + A * self.x + B) % P
        return lhs == rhs

    def is_at_infinity(self) -> bool:
        """
        Check if the point is the point at infinity.

        :return: True if the point is at infinity, False otherwise.
        """
        return self.x is None and self.y is None

    @classmethod
    def sec_deserialize(cls, hex_public_key: str) -> Point:
        """
        Deserialize a SEC 1 compressed hex-encoded public key to a Point
        object.

        Parameters:
        hex_public_key (str): Hexadecimal string of 33 bytes representing the
        compressed public key.

        Returns:
        Point: An instance of Point corresponding to the deserialized public
        key.

        Raises:
        ValueError: If the input is not a valid hex string, does not represent
        a valid point, or has incorrect length.
        """
        hex_bytes = bytes.fromhex(hex_public_key)
        if len(hex_bytes) != 33:
            raise ValueError("SEC1 compressed public key must be 33 bytes.")

        prefix = hex_bytes[0]
        if prefix not in (2, 3):
            raise ValueError("Invalid SEC1 prefix byte.")

        x_bytes = hex_bytes[1:]
        x = int.from_bytes(x_bytes, "big")
        y_squared = (x * x * x + A * x + B) % P
        y = pow(y_squared, (P + 1) // 4, P)
        if pow(y, 2, P) != y_squared:
            raise ValueError("Computed y does not satisfy curve equation.")

        # Choose the correct y based on the prefix
        if (y % 2 == 0 and prefix == 2) or (y % 2 == 1 and prefix == 3):
            pass  # y is correct
        else:
            y = P - y  # Use the other root

        return cls(x, y)

    def sec_serialize(self) -> bytes:
        """
        Serialize the point to its SEC1 compressed format.

        :return: The SEC1 compressed format of the point.
        :raises ValueError: If the point is at infinity.
        """
        if self.is_at_infinity():
            raise ValueError("Cannot serialize the point at infinity.")
        assert self.x is not None and self.y is not None

        prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
        x_bytes = self.x.to_bytes(32, "big")
        return prefix + x_bytes

    def __eq__(self, other: Any) -> bool:
        """
        Check if this point is equal to another point.

        :param other: The other point to compare with.
        :return: True if both points are equal, False otherwise.
        """
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y

    def __neg__(self) -> Point:
        """
        Negate the point on the elliptic curve.

        :return: The negation of the point.
        """
        if self.is_at_infinity():
            return self
        assert self.y is not None and self.x is not None
        return Point(self.x, (-self.y) % P)

    def __add__(self, other: Point) -> Point:
        """
        Add two points on the elliptic curve.

        :param other: The other point to add.
        :return: The sum of the two points.
        """
        if not isinstance(other, Point):
            raise TypeError("Cannot add Point and non-Point objects.")

        # Handle special cases involving the point at infinity
        if self.is_at_infinity():
            return other
        if other.is_at_infinity():
            return self

        assert self.x is not None and self.y is not None
        assert other.x is not None and other.y is not None

        # Handle point doubling
        if self == other:
            if self.y == 0:
                return Point(None, None)  # Point at infinity
            s = (3 * self.x * self.x * pow(2 * self.y, P - 2, P)) % P
        else:
            if self.x == other.x:
                return Point(None, None)  # Point at infinity
            s = ((other.y - self.y) * pow(other.x - self.x, P - 2, P)) % P

        x_r = (s * s - self.x - other.x) % P
        y_r = (s * (self.x - x_r) - self.y) % P

        return Point(x_r, y_r)

    def __sub__(self, other: Point) -> Point:
        """
        Subtract one point from another.

        :param other: The point to subtract.
        :return: The result of the subtraction.
        """
        if not isinstance(other, Point):
            raise TypeError("Cannot subtract non-Point from Point.")
        return self + (-other)

    def __rmul__(self, scalar: int) -> Point:
        """
        Multiply the point by an integer scalar using the double-and-add
        algorithm.

        :param scalar: The integer to multiply by.
        :return: The result of the scalar multiplication.
        """
        if not isinstance(scalar, int):
            raise TypeError("Scalar multiplication requires an integer.")

        scalar = scalar % N  # Ensure scalar is within the group order
        result = Point(None, None)  # Initialize to point at infinity
        addend = self

        while scalar:
            if scalar & 1:
                result += addend
            addend += addend
            scalar >>= 1

        return result

    def __str__(self) -> str:
        """
        Return a human-readable string representation of the point.

        :return: A string representing the point.
        """
        if self.is_at_infinity():
            return "Point at Infinity"
        assert self.x is not None and self.y is not None
        return f"Point(x={hex(self.x)}, y={hex(self.y)})"

    def __repr__(self) -> str:
        """
        Return an unambiguous string representation of the point.

        :return: A string that can be used to recreate the object.
        """
        return f"Point(x={self.x}, y={self.y})"


# The generator point G
G: Point = Point(Gx, Gy)
