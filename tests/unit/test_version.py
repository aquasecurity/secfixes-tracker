import pytest
from secfixes_tracker.version import APKVersion


def test_repr():
    v = APKVersion('1.2.3-r1')
    assert repr(v) == '<APKVersion 1.2.3-r1>'


def test_equal_versions():
    v1 = APKVersion('1.0.0')
    v2 = APKVersion('1.0.0')
    assert v1 == v2


def test_less_than_versions():
    v1 = APKVersion('1.0.0')
    v2 = APKVersion('2.0.0')
    assert v1 < v2


def test_greater_than_versions():
    v1 = APKVersion('2.0.0')
    v2 = APKVersion('1.0.0')
    assert v1 > v2


def test_not_equal_versions():
    v1 = APKVersion('1.0.0')
    v2 = APKVersion('2.0.0')
    assert v1 != v2


def test_less_than_equal_versions():
    v1 = APKVersion('1.0.0')
    v2 = APKVersion('2.0.0')
    v3 = APKVersion('1.0.0')
    assert v1 <= v2
    assert v1 <= v3


def test_greater_than_equal_versions():
    v1 = APKVersion('2.0.0')
    v2 = APKVersion('1.0.0')
    v3 = APKVersion('2.0.0')
    assert v1 >= v2
    assert v1 >= v3
