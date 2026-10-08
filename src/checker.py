"""비밀번호 보안 등급 평가 프로그램."""

import getpass
import secrets
import string
import sys

SPECIAL_CHARS = "!@#$%^&*"
MIN_LENGTH = 8


def check_rules(password: str) -> list[tuple[str, bool]]:
    """각 검사 규칙의 (설명, 충족 여부) 목록을 반환한다."""
    return [
        (f"{MIN_LENGTH}자리 이상", len(password) >= MIN_LENGTH),
        (
            "대문자와 소문자 혼합",
            any(c.isupper() for c in password) and any(c.islower() for c in password),
        ),
        ("숫자 포함", any(c.isdigit() for c in password)),
        (f"특수문자({SPECIAL_CHARS}) 포함", any(c in SPECIAL_CHARS for c in password)),
    ]


def get_grade(passed: int) -> str:
    """충족한 조건 개수로 보안 등급을 반환한다."""
    if passed <= 1:
        return "취약"
    if passed <= 3:
        return "보통"
    return "강력"


GRADE_ICONS = {"취약": "🔴", "보통": "🟡", "강력": "🟢"}


def format_report(password: str) -> str:
    """검사 결과 리포트 문자열을 만든다. 비밀번호 자체는 포함하지 않는다."""
    results = check_rules(password)
    passed = sum(ok for _, ok in results)
    grade = get_grade(passed)

    lines = ["=" * 34, "   🔐 비밀번호 보안 검사 결과", "=" * 34]
    for desc, ok in results:
        lines.append(f"  {'✅' if ok else '❌'}  {desc}")
    lines += [
        "-" * 34,
        f"  충족 조건: {passed}/{len(results)}",
        f"  보안 등급: {GRADE_ICONS[grade]} {grade}",
        "=" * 34,
    ]
    return "\n".join(lines)


def generate_password(length: int = 12) -> str:
    """'강력' 등급을 만족하는 무작위 추천 비밀번호를 생성한다."""
    length = max(length, MIN_LENGTH)
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, SPECIAL_CHARS]
    # 각 조건을 하나씩 보장하고 나머지는 전체 문자에서 무작위로 채운다.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice("".join(pools)) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows 콘솔에서 아이콘 깨짐 방지
    password = getpass.getpass("검사할 비밀번호를 입력하세요 (입력 내용은 화면에 표시되지 않습니다): ")
    print(format_report(password))
    print(f"\n💡 추천 비밀번호 (강력): {generate_password()}")


if __name__ == "__main__":
    main()
