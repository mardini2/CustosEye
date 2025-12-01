from __future__ import annotations

import math

import pytest

import algorithm.csc_engine as csc


def test_safe_lower_and_basename_never_throw():
    assert csc._safe_lower(None) == ""
    assert csc._safe_lower(123) == "123"
    assert isinstance(csc._basename("weird///path///file.txt"), str)


@pytest.mark.parametrize(
    "s, expect_hexish",
    [
        ("abc123def456", True),
        ("deadbeefcafebabefeedface", True),
        ("normalname.exe", False),
        ("short", False),
    ],
)
def test_looks_hexish(s, expect_hexish):
    assert csc._looks_hexish(s) is expect_hexish


def test_entropy_reasonable_ranges():
    assert math.isclose(csc._shannon_entropy(""), 0.0)
    low = csc._shannon_entropy("aaaaaaaaaa")
    mid = csc._shannon_entropy("abcabcabcabc")
    high = csc._shannon_entropy("x7Qp9Zm2Kc1")
    assert 0.0 <= low <= mid <= high <= 4.5  # crude but stable bounds


def test_to_float_and_safe_int():
    assert csc._to_float("3.5") == 3.5
    assert csc._to_float("nope") is None
    assert csc._safe_int("12") == 12
    assert csc._safe_int("xx") == -1
