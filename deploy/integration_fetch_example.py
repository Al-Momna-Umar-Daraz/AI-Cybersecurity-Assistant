import os
import re
import time
from pathlib import Path

import requests
from openai import OpenAI

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None


BASE_DIR = Path(__file__).resolve().parent.parent
if load_dotenv is not None:
    load_dotenv(BASE_DIR / ".env")


OPENAI_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4").strip()
HIBP_KEY = os.getenv("HIBP_API_KEY", "").strip()
FACECHECK_TOKEN = os.getenv("FACECHECK_API_TOKEN", "").strip()


def fetch_openai_analysis(prompt: str) -> str:
    if not OPENAI_KEY:
        return "OPENAI_API_KEY missing."
    client = OpenAI(api_key=OPENAI_KEY)
    resp = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return (resp.choices[0].message.content or "").strip()


def check_breach(email: str):
    if not HIBP_KEY:
        return {"ok": False, "message": "HIBP_API_KEY missing."}
    if "@" not in email:
        return {"ok": False, "message": "Invalid email."}

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {"hibp-api-key": HIBP_KEY, "user-agent": "AI-Cybersecurity-Assistant"}
    r = requests.get(url, headers=headers, timeout=20)

    if r.status_code == 404:
        return {"ok": True, "message": "No breaches found.", "breaches": []}
    if r.status_code != 200:
        return {"ok": False, "message": f"HIBP error: HTTP {r.status_code}"}

    return {"ok": True, "message": "Breach records found.", "breaches": r.json()}


def search_face(image_path: str, demo: bool = True):
    """
    FaceCheck flow:
    1) POST /api/upload_pic with multipart image
    2) Poll POST /api/search with id_search until output is returned
    """
    if not FACECHECK_TOKEN:
        return {"ok": False, "message": "FACECHECK_API_TOKEN missing."}
    p = Path(image_path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "message": "Image file not found."}

    headers = {"accept": "application/json", "Authorization": FACECHECK_TOKEN}
    with p.open("rb") as f:
        upload = requests.post(
            "https://facecheck.id/api/upload_pic",
            headers=headers,
            files={"images": (p.name, f, "application/octet-stream")},
            data={"id_search": ""},
            timeout=30,
        )
    if upload.status_code != 200:
        return {"ok": False, "message": f"FaceCheck upload failed: HTTP {upload.status_code}"}

    upload_data = upload.json()
    if upload_data.get("error"):
        return {"ok": False, "message": str(upload_data.get("error"))}

    id_search = str(upload_data.get("id_search", "")).strip()
    if not id_search:
        return {"ok": False, "message": "No id_search returned."}

    payload = {"id_search": id_search, "with_progress": True, "status_only": False, "demo": bool(demo)}
    for _ in range(45):
        s = requests.post(
            "https://facecheck.id/api/search",
            headers={**headers, "Content-Type": "application/json"},
            json=payload,
            timeout=25,
        )
        if s.status_code != 200:
            return {"ok": False, "message": f"FaceCheck search failed: HTTP {s.status_code}"}
        data = s.json()
        if data.get("error"):
            return {"ok": False, "message": str(data.get("error"))}
        output = data.get("output")
        if isinstance(output, dict) and isinstance(output.get("items"), list):
            return {"ok": True, "items": output.get("items", [])}
        time.sleep(1)

    return {"ok": False, "message": "FaceCheck timed out waiting for results."}


def validate_iban_format(iban: str):
    """
    Local format check only (not bank API validation).
    Pakistan IBAN starts with PK and total length is 24.
    """
    value = re.sub(r"\s+", "", str(iban or "").upper())
    if not value:
        return {"ok": False, "message": "IBAN is empty."}
    if not re.match(r"^[A-Z0-9]+$", value):
        return {"ok": False, "message": "IBAN has invalid characters."}
    if not value.startswith("PK"):
        return {"ok": False, "message": "Not a Pakistan IBAN (must start with PK)."}
    if len(value) != 24:
        return {"ok": False, "message": "Pakistan IBAN must be 24 characters."}
    return {"ok": True, "message": "IBAN format looks valid."}


if __name__ == "__main__":
    print("Integration helper ready.")
    print("- fill .env keys first")
    print("- call functions from this module in your tests")
