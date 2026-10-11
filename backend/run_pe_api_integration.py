import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


BASE = "http://127.0.0.1:8000"

EMAIL = "autorev.owner.a@example.com"
PASSWORD = "AutoRev-Owner-A-123!"

FILE_PATH = r"storage\uploads\1224ac91_test_mitre.exe"
FILE_NAME = "1224ac91_test_mitre.exe"


def post(path, payload):
    """Send a JSON POST request and return (status, JSON response)."""
    request = Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(
                response.read().decode("utf-8")
            )

    except HTTPError as exc:
        try:
            data = json.loads(exc.read().decode("utf-8"))
        except Exception:
            data = {}

        return exc.code, data

    except URLError as exc:
        print("REQUEST ERROR:", exc)
        raise SystemExit(1)


# ============================================================
# 1. ENSURE TEST ACCOUNT EXISTS
# ============================================================

register_status, register_data = post(
    "/auth/register",
    {
        "email": EMAIL,
        "username": "autorev_owner_a",
        "password": PASSWORD,
        "full_name": "AutoRev Owner A",
    },
)

print("REGISTER STATUS:", register_status)

if register_status not in (200, 201, 409):
    print("REGISTER RESPONSE:", register_data)
    raise SystemExit(1)


# ============================================================
# 2. LOGIN
# ============================================================

login_status, login_data = post(
    "/auth/login",
    {
        "email": EMAIL,
        "password": PASSWORD,
    },
)

print("LOGIN STATUS:", login_status)

if login_status != 200:
    print("LOGIN RESPONSE:", login_data)
    raise SystemExit(1)

token = login_data["access_token"]


# ============================================================
# 3. LOAD REAL PE FIXTURE
# ============================================================

try:
    with open(FILE_PATH, "rb") as file:
        file_data = file.read()

except FileNotFoundError:
    print("ERROR: PE fixture not found:")
    print(FILE_PATH)
    raise SystemExit(1)

print("PE FILE:", FILE_PATH)
print("PE FILE SIZE:", len(file_data), "bytes")


# ============================================================
# 4. BUILD MULTIPART UPLOAD
# ============================================================

boundary = "----AutoRevPEBoundary"

body = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="file"; '
    f'filename="{FILE_NAME}"\r\n'
    "Content-Type: application/octet-stream\r\n"
    "\r\n"
).encode("utf-8") + file_data + (
    f"\r\n--{boundary}--\r\n"
).encode("utf-8")


request = Request(
    BASE + "/upload",
    data=body,
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    },
    method="POST",
)


# ============================================================
# 5. UPLOAD
# ============================================================

try:
    with urlopen(request, timeout=30) as response:
        upload_status = response.status
        upload_data = json.loads(
            response.read().decode("utf-8")
        )

    print("UPLOAD STATUS:", upload_status)
    print("UPLOAD RESPONSE:")
    print(json.dumps(upload_data, indent=2, default=str))

except HTTPError as exc:
    print("UPLOAD STATUS:", exc.code)

    try:
        error_data = json.loads(
            exc.read().decode("utf-8")
        )
        print(
            "UPLOAD RESPONSE:",
            json.dumps(error_data, indent=2, default=str),
        )
    except Exception:
        print("UPLOAD RESPONSE:", exc.read().decode("utf-8"))

    raise SystemExit(1)

except Exception as exc:
    print(
        "UPLOAD ERROR:",
        type(exc).__name__,
        str(exc),
    )
    raise SystemExit(1)


# ============================================================
# 6. GET JOB ID
# ============================================================

job_id = upload_data.get("job_id")

if not job_id:
    print("ERROR: Upload response did not contain job_id.")
    raise SystemExit(1)

print("JOB ID:", job_id)


# ============================================================
# 7. REQUEST ACTUAL ANALYSIS RESULT
# ============================================================

request = Request(
    BASE + f"/analysis/{job_id}",
    headers={
        "Authorization": f"Bearer {token}",
    },
    method="GET",
)


try:
    with urlopen(request, timeout=180) as response:
        analysis_status = response.status
        analysis_data = json.loads(
            response.read().decode("utf-8")
        )

    print("ANALYSIS STATUS:", analysis_status)

except HTTPError as exc:
    print("ANALYSIS STATUS:", exc.code)

    try:
        error_data = json.loads(
            exc.read().decode("utf-8")
        )
        print(
            "ANALYSIS RESPONSE:",
            json.dumps(error_data, indent=2, default=str),
        )
    except Exception:
        print("ANALYSIS RESPONSE:", exc.read().decode("utf-8"))

    raise SystemExit(1)

except Exception as exc:
    print(
        "ANALYSIS ERROR:",
        type(exc).__name__,
        str(exc),
    )
    raise SystemExit(1)


# ============================================================
# 8. RESPONSE STRUCTURE
# ============================================================

print("\n=== ANALYSIS RESPONSE KEYS ===")

for key in analysis_data.keys():
    print(" -", key)


# ============================================================
# 9. FULL ANALYSIS OUTPUT
# ============================================================

print("\n=== ANALYSIS OUTPUT ===")

print(
    json.dumps(
        analysis_data,
        indent=2,
        default=str,
    )
)


# ============================================================
# 10. BASIC ANALYSIS SUMMARY
#
# IMPORTANT:
# Current API does NOT return:
#
#     analysis_data["result"]
#
# The analysis fields are directly under analysis_data.
# ============================================================

print("\n=== ANALYSIS SUMMARY ===")

print(
    "FUNCTION ANALYSIS:",
    len(
        analysis_data.get(
            "analysis",
            {}
        ).get(
            "results",
            []
        )
    )
    if isinstance(analysis_data.get("analysis"), dict)
    else "N/A",
)

print(
    "IMPORTS:",
    len(
        analysis_data.get(
            "imports",
            []
        )
    )
)

print(
    "STRINGS:",
    len(
        analysis_data.get(
            "strings",
            []
        )
    )
)

print(
    "BEHAVIORS:",
    analysis_data.get(
        "behaviors",
        []
    )
)

print(
    "CAPABILITIES:",
    analysis_data.get(
        "capabilities",
        []
    )
)

print(
    "RISK:",
    analysis_data.get(
        "risk"
    )
)

print(
    "CVSS:",
    analysis_data.get(
        "cvss_results"
    )
)

print(
    "ARISE VERDICT:",
    analysis_data.get(
        "arise_verdict"
    )
)


# ============================================================
# 11. MITRE FUSION DEBUG
#
# This is the important section for our current investigation.
# ============================================================

final_mitre = analysis_data.get(
    "final_mitre",
    {}
)

print("\n=== MITRE FUSION DEBUG ===")


print("\nBEHAVIOR MITRE:")
print(
    json.dumps(
        analysis_data.get(
            "mitre_results",
            {}
        ),
        indent=2,
        default=str,
    )
)


print("\nCAPABILITY MITRE:")
print(
    json.dumps(
        analysis_data.get(
            "capability_mitre_results",
            {}
        ),
        indent=2,
        default=str,
    )
)


print("\nFINAL MITRE:")
print(
    json.dumps(
        final_mitre,
        indent=2,
        default=str,
    )
)


print("\nFINAL MITRE SOURCES:")
print(
    json.dumps(
        final_mitre.get(
            "sources",
            {}
        )
        if isinstance(final_mitre, dict)
        else {},
        indent=2,
        default=str,
    )
)


# ============================================================
# 12. MITRE TECHNIQUE COMPARISON
# ============================================================

behavior_mitre = analysis_data.get(
    "mitre_results",
    {}
)

capability_mitre = analysis_data.get(
    "capability_mitre_results",
    {}
)


behavior_techniques = set(
    behavior_mitre.get(
        "mitre_techniques",
        []
    )
    if isinstance(behavior_mitre, dict)
    else []
)

capability_techniques = set(
    capability_mitre.get(
        "mitre_techniques",
        []
    )
    if isinstance(capability_mitre, dict)
    else []
)

final_techniques = set(
    final_mitre.get(
        "mitre_techniques",
        []
    )
    if isinstance(final_mitre, dict)
    else []
)


print("\n=== MITRE TECHNIQUE COMPARISON ===")

print(
    "Behavior techniques:",
    len(behavior_techniques),
)

print(
    "Capability techniques:",
    len(capability_techniques),
)

print(
    "Final techniques:",
    len(final_techniques),
)


print(
    "\nBehavior-only techniques:"
)

print(
    sorted(
        behavior_techniques
        - capability_techniques
    )
)


print(
    "\nCapability-only techniques:"
)

print(
    sorted(
        capability_techniques
        - behavior_techniques
    )
)


print(
    "\nTechniques present in BOTH:"
)

print(
    sorted(
        behavior_techniques
        & capability_techniques
    )
)


# ============================================================
# 13. FINAL SOURCE ATTRIBUTION
# ============================================================

print("\n=== FINAL MITRE SOURCE ATTRIBUTION ===")

sources = (
    final_mitre.get("sources", {})
    if isinstance(final_mitre, dict)
    else {}
)

if isinstance(sources, dict):
    for technique in sorted(sources):
        print(
            f"{technique}: {sources[technique]}"
        )
else:
    print("No source attribution available.")


print("\n=== PE API TEST COMPLETE ===")