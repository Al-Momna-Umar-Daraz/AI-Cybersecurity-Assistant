from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"


def parse_env(path: Path):
    data = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def is_real(value: str):
    text = (value or "").strip().lower()
    if not text:
        return False
    blocked = (
        "replace_with_",
        "ca-pub-xxxxxxxx",
        "pk00demo",
    )
    return not text.startswith(blocked)


def main():
    env = parse_env(ENV_PATH)
    if not env:
        print("ERROR: .env file not found in project root.")
        return

    checks = [
        ("FLASK_SECRET_KEY", is_real(env.get("FLASK_SECRET_KEY", ""))),
        ("OPENAI_API_KEY", is_real(env.get("OPENAI_API_KEY", ""))),
        ("HIBP_API_KEY", is_real(env.get("HIBP_API_KEY", ""))),
        ("FACECHECK_API_TOKEN", is_real(env.get("FACECHECK_API_TOKEN", ""))),
        ("GOOGLE_CLIENT_ID", is_real(env.get("GOOGLE_CLIENT_ID", ""))),
        ("GOOGLE_CLIENT_SECRET", is_real(env.get("GOOGLE_CLIENT_SECRET", ""))),
        ("GOOGLE_REDIRECT_URI", is_real(env.get("GOOGLE_REDIRECT_URI", ""))),
        ("PK_ACCOUNT_TITLE", is_real(env.get("PK_ACCOUNT_TITLE", ""))),
        (
            "PK_ACCOUNT_NUMBER_OR_IBAN",
            is_real(env.get("PK_ACCOUNT_NUMBER", "")) or is_real(env.get("PK_IBAN", "")),
        ),
        ("SESSION_COOKIE_SECURE_EQ_1", env.get("SESSION_COOKIE_SECURE", "0") == "1"),
        ("ENFORCE_HTTPS_EQ_1", env.get("ENFORCE_HTTPS", "0") == "1"),
        ("BANK_TRANSFER_AUTO_APPROVE_EQ_0", env.get("BANK_TRANSFER_AUTO_APPROVE", "1") == "0"),
        ("FACECHECK_DEMO_EQ_0", env.get("FACECHECK_DEMO", "1") == "0"),
    ]

    failed = [name for name, ok in checks if not ok]

    print("ENV READINESS REPORT")
    print("====================")
    for name, ok in checks:
        print(f"[{'OK' if ok else 'MISSING'}] {name}")

    print()
    if failed:
        print("STATUS: NOT READY")
        print("Fix these:")
        for name in failed:
            print(f"- {name}")
    else:
        print("STATUS: READY FOR PRODUCTION CONFIG CHECK")


if __name__ == "__main__":
    main()
