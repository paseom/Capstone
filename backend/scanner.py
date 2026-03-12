import os
import requests
import subprocess
import json
from zapv2 import ZAPv2

OJS_URL = os.getenv("OJS_TARGET_URL", "http://ojs:80")
ZAP_HOST = os.getenv("ZAP_HOST", "zap")
ZAP_PORT = os.getenv("ZAP_PORT", "8090")

def run_zap_scan() -> list[dict]:
    """
    Trigger OWASP ZAP active scan terhadap OJS.
    Return list of findings.
    """
    findings = []
    try:
        zap = ZAPv2(proxies={"http": f"http://{ZAP_HOST}:{ZAP_PORT}"})

        print(f"[ZAP] Starting scan on {OJS_URL}")
        zap.urlopen(OJS_URL)

        scan_id = zap.ascan.scan(OJS_URL)
        print(f"[ZAP] Scan ID: {scan_id}")

        # Tunggu sampai scan selesai
        import time
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"[ZAP] Progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        alerts = zap.core.alerts()
        for alert in alerts:
            findings.append({
                "source": "zap",
                "name": alert.get("name"),
                "risk": alert.get("risk"),          # High / Medium / Low / Informational
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
    """
    Jalankan Nikto lewat Docker container yang sudah jalan.
    Return list of findings.
    """
    findings = []
    try:
        print(f"[Nikto] Starting scan on {OJS_URL}")
        result = subprocess.run(
            [
                "docker", "exec", "ojs-nikto",
                "nikto", "-h", OJS_URL, "-Format", "json", "-output", "/tmp/nikto_result.json"
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Baca hasil JSON
        read_result = subprocess.run(
            ["docker", "exec", "ojs-nikto", "cat", "/tmp/nikto_result.json"],
            capture_output=True, text=True
        )

        data = json.loads(read_result.stdout)
        for item in data.get("vulnerabilities", []):
            findings.append({
                "source": "nikto",
                "name": item.get("id"),
                "risk": item.get("OSVDB", "Unknown"),
                "description": item.get("msg"),
                "url": item.get("url"),
                "method": item.get("method"),
            })

        print(f"[Nikto] Found {len(findings)} issues")

    except Exception as e:
        print(f"[Nikto] Error: {e}")
        findings.append({"source": "nikto", "error": str(e)})

    return findings