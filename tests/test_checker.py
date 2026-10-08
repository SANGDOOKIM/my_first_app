import pytest

from src.checker import check_rules, format_report, generate_password, get_grade


def test_generated_password_is_strong():
    for _ in range(100):
        pw = generate_password()
        assert len(pw) == 12
        assert get_grade(sum(ok for _, ok in check_rules(pw))) == "강력"


def test_generated_password_enforces_min_length():
    assert len(generate_password(3)) == 8


@pytest.mark.parametrize(
    "password, expected",
    [
        ("", "취약"),
        ("abcdefgh", "취약"),  # 길이만 충족 (1개)
        ("abcdefg1", "보통"),  # 길이 + 숫자 (2개)
        ("Abcdefg1", "보통"),  # 3개
        ("Abcdef1!", "강력"),  # 4개
    ],
)
def test_grade(password, expected):
    passed = sum(ok for _, ok in check_rules(password))
    assert get_grade(passed) == expected


def test_mixed_case_requires_both():
    assert not dict(check_rules("ABCDEFGH"))["대문자와 소문자 혼합"]


def test_report_does_not_leak_password():
    assert "Abcdef1!" not in format_report("Abcdef1!")
