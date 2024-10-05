import pytest
from hypothesis import settings, given, strategies as st

from src.ecc import Point, G, N, P

# Strategy for scalars in the range [0, N - 1]
scalars = st.integers(min_value=0, max_value=N - 1)

# Point at infinity
O: Point = Point(None, None)


@given(k1=scalars, k2=scalars)
def test_addition_commutativity(k1: int, k2: int) -> None:
    P = k1 * G
    Q = k2 * G
    assert P + Q == Q + P


@given(k1=scalars, k2=scalars, k3=scalars)
def test_addition_associativity(k1: int, k2: int, k3: int) -> None:
    P = k1 * G
    Q = k2 * G
    R = k3 * G
    assert (P + Q) + R == P + (Q + R)


@given(k=scalars, k1=scalars, k2=scalars)
@settings(deadline=500)
def test_scalar_multiplication_distributivity(
    k: int, k1: int, k2: int
) -> None:
    P = k1 * G
    Q = k2 * G
    left = k * (P + Q)
    right = k * P + k * Q
    assert left == right


@given(k=scalars)
def test_negation(k: int) -> None:
    P = k * G
    assert P + (-P) == O


@given(k=scalars)
def test_point_doubling(k: int) -> None:
    P = k * G
    assert 2 * P == P + P


@given(k1=scalars, k2=scalars)
def test_point_subtraction_property(k1: int, k2: int) -> None:
    P = k1 * G
    Q = k2 * G
    scalar_diff = (k1 - k2) % N
    left_side = P - Q
    right_side = scalar_diff * G
    assert left_side == right_side


@given(k1=scalars, k2=scalars)
def test_point_subtraction_inverse(k1: int, k2: int) -> None:
    P = k1 * G
    Q = k2 * G
    result = (P - Q) + Q
    assert result == P


def test_point_subtraction_zero() -> None:
    P = 7 * G
    assert P - P == O


def test_generator_order() -> None:
    assert N * G == O


@given(k=scalars)
def test_multiplication_by_zero(k: int) -> None:
    P = k * G
    assert 0 * P == O


@given(k=scalars)
def test_serialization_deserialization(k: int) -> None:
    P = k * G
    if P.is_at_infinity():
        return
    sec = P.sec_serialize()
    P_deserialized = Point.sec_deserialize(sec.hex())
    assert P == P_deserialized


@given(k1=scalars, k2=scalars)
def test_point_equality(k1: int, k2: int) -> None:
    P = k1 * G
    Q = k2 * G
    if k1 == k2:
        assert P == Q
    else:
        assert P != Q


def test_point_invalid_infinity_representation() -> None:
    with pytest.raises(
        ValueError,
        match="Both x and y should be None for the point at infinity.",
    ):
        Point(None, 1)
    with pytest.raises(
        ValueError,
        match="Both x and y should be None for the point at infinity.",
    ):
        Point(1, None)


def test_point_coordinates_out_of_range() -> None:
    with pytest.raises(
        ValueError, match="Point coordinates must be within field range."
    ):
        Point(-1, 1)
    with pytest.raises(
        ValueError, match="Point coordinates must be within field range."
    ):
        Point(1, -1)
    with pytest.raises(
        ValueError, match="Point coordinates must be within field range."
    ):
        Point(P, 1)
    with pytest.raises(
        ValueError, match="Point coordinates must be within field range."
    ):
        Point(1, P)


def test_point_not_on_curve() -> None:
    x = 1
    y = 1
    with pytest.raises(
        ValueError, match=r"Point \(1, 1\) is not on the curve."
    ):
        Point(x, y)


def test_is_on_curve_at_infinity() -> None:
    O: Point = Point(None, None)
    assert O.is_on_curve() is True


def test_sec_deserialize_invalid_length() -> None:
    invalid_key = "02" + "00" * 31  # 32 bytes instead of 33
    with pytest.raises(
        ValueError, match="SEC1 compressed public key must be 33 bytes."
    ):
        Point.sec_deserialize(invalid_key)


def test_sec_deserialize_invalid_prefix() -> None:
    invalid_key = "04" + "00" * 32  # Invalid prefix '04'
    with pytest.raises(ValueError, match="Invalid SEC1 prefix byte."):
        Point.sec_deserialize(invalid_key)


def test_sec_deserialize_invalid_y() -> None:
    invalid_x = P - 1  # An x value that's unlikely to correspond to a valid y
    invalid_key = "02" + f"{invalid_x:064x}"
    with pytest.raises(
        ValueError, match="Computed y does not satisfy curve equation."
    ):
        Point.sec_deserialize(invalid_key)


def test_sec_serialize_at_infinity() -> None:
    O: Point = Point(None, None)
    with pytest.raises(
        ValueError, match="Cannot serialize the point at infinity."
    ):
        O.sec_serialize()


def test_point_equality_with_non_point() -> None:
    P = G
    assert (P == "not a point") is False


def test_add_non_point() -> None:
    P = G
    with pytest.raises(
        TypeError, match="Cannot add Point and non-Point objects."
    ):
        P + "not a point"  # type: ignore


def test_subtract_non_point() -> None:
    P = G
    with pytest.raises(
        TypeError, match="Cannot subtract non-Point from Point."
    ):
        P - "not a point"  # type: ignore


def test_scalar_multiplication_non_integer() -> None:
    P = G
    with pytest.raises(
        TypeError, match="Scalar multiplication requires an integer."
    ):
        "not an int" * P  # type: ignore


def test_str_point_at_infinity() -> None:
    O: Point = Point(None, None)
    assert str(O) == "Point at Infinity"


def test_str_regular_point() -> None:
    P = G
    assert P.x is not None and P.y is not None
    expected_str = f"Point(x={hex(P.x)}, y={hex(P.y)})"
    assert str(P) == expected_str


def test_repr_point() -> None:
    P = G
    expected_repr = f"Point(x={P.x}, y={P.y})"
    assert repr(P) == expected_repr


def test_point_doubling_y_zero() -> None:
    P = G
    original_y = P.y
    try:
        P.y = 0  # type: ignore
        result = P + P
        assert result.is_at_infinity()
    finally:
        P.y = original_y  # Restore the original y value
