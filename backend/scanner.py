import os
import time
import subprocess
import requests

OJS_URL = os.getenv("OJS_TARGET_URL", "http://ojs:80")
ZAP_HOST = os.getenv("ZAP_HOST", "zap")
ZAP_PORT = os.getenv("ZAP_PORT", "8090")
ZAP_BASE = f"http://{ZAP_HOST}:{ZAP_PORT}"


def zap_get(path: str, params: dict = {}) -> dict:
    url = f"{ZAP_BASE}{path}"
    r = requests.get(url, params=params, timeout=30)
    return r.json()


def wait_for_zap(retries=20, delay=5):
    for i in range(retries):
        try:
            data = zap_get("/JSON/core/view/version/")
            if data.get("version"):
                print(f"[ZAP] Ready! Version: {data['version']}")
                return True
        except Exception as e:
            print(f"[ZAP] Not ready ({i+1}/{retries}): {e}")
            time.sleep(delay)
    return False


def run_zap_scan() -> list[dict]:
    """
    ZAP Spider + Passive Scan saja (ringan, tidak crash).
    Active scan dinonaktifkan untuk prototype.
    """
    findings = []
    try:
        if not wait_for_zap():
            raise Exception("ZAP tidak bisa diakses")

        # Spider saja (passive scan otomatis jalan saat spider)
        print(f"[ZAP] Starting spider on {OJS_URL}")
        spider = zap_get("/JSON/spider/action/scan/", {"url": OJS_URL, "maxChildren": "10"})
        spider_id = spider.get("scan", "0")

        while True:
            status = zap_get("/JSON/spider/view/status/", {"scanId": spider_id})
            pct = int(status.get("status", 0))
            print(f"[ZAP] Spider: {pct}%")
            if pct >= 100:
                break
            time.sleep(5)
        print("[ZAP] Spider done")

        # Tunggu passive scan selesai
        time.sleep(10)

        # Ambil alerts dari passive scan
        alerts_resp = zap_get("/JSON/core/view/alerts/", {
            "baseurl": OJS_URL,
            "start": "0",
            "count": "100"
        })
        alerts = alerts_resp.get("alerts", [])

        for alert in alerts:
            findings.append({
                "source": "zap",
                "name": alert.get("name"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "description": alert.get("description"),
                "url": alert.get("url"),
                "solution": alert.get("solution"),
            })

        print(f"[ZAP] Found {len(findings)} alerts")

    except Exception as e:
        print(f"[ZAP] Error: {e}")
        findings.append({"source": "zap", "error": str(e)})

    return findings


def run_nikto_scan() -> list[dict]:
    findings = []
    try:
        print(f"[Nikto] Starting scan on {OJS_URL}")

        result = subprocess.run(
            [
                "perl", "/opt/nikto/program/nikto.pl",
                "-h", OJS_URL,
                "-Format", "txt",
                "-nointeractive",
                "-Tuning", "1",   # hanya test file berbahaya (ringan)
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout + result.stderr
        print(f"[Nikto] Output preview:\n{output[:800]}")

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("+") and len(line) > 5:
                findings.append({
                    "source": "nikto",
                    "name": "Nikto Finding",
                    "risk": "Medium",
                    "description": line,
                    "url": OJS_URL,
                })

        print(f"[Nikto] Found {len(findings)} issues")

    except Exception as e:
        print(f"[Nikto] Error: {e}")
        findings.append({"source": "nikto", "error": str(e)})

    return findings