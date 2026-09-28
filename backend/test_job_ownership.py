import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError

BASE = "http://127.0.0.1:8000"

users = [
    {
        "email": "autorev.owner.a@example.com",
        "username": "autorev_owner_a",
        "password": "AutoRev-Owner-A-123!",
        "full_name": "AutoRev Owner A",
    },
    {
        "email": "autorev.owner.b@example.com",
        "username": "autorev_owner_b",
        "password": "AutoRev-Owner-B-123!",
        "full_name": "AutoRev Owner B",
    },
]

def post(path, payload):
    request = Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())

tokens = []

for user in users:
    status, data = post("/auth/register", user)
    print("REGISTER:", user["username"], status)

    status, data = post(
        "/auth/login",
        {
            "email": user["email"],
            "password": user["password"],
        },
    )

    print("LOGIN:", user["username"], status)
    tokens.append(data["access_token"])

token_a = tokens[0]
token_b = tokens[1]

# Create a harmless temporary text upload as User A.
boundary = "----AutoRevOwnershipBoundary"
file_data = b"AutoRev ownership security test"

body = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="file"; filename="ownership_test.txt"\r\n'
    "Content-Type: text/plain\r\n"
    "\r\n"
).encode() + file_data + (
    f"\r\n--{boundary}--\r\n"
).encode()

request = Request(
    BASE + "/upload",
    data=body,
    headers={
        "Authorization": f"Bearer {token_a}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    },
    method="POST",
)

with urlopen(request, timeout=15) as response:
    upload_data = json.loads(response.read().decode())

job_id = upload_data["job_id"]

print("UPLOAD STATUS:", response.status)
print("JOB ID:", job_id)

# User A accesses own job.
request = Request(
    BASE + f"/analysis/{job_id}",
    headers={"Authorization": f"Bearer {token_a}"},
)

try:
    with urlopen(request, timeout=15) as response:
        print("OWNER ACCESS STATUS:", response.status)
except HTTPError as exc:
    print("OWNER ACCESS STATUS:", exc.code)

# User B attempts User A's job.
request = Request(
    BASE + f"/analysis/{job_id}",
    headers={"Authorization": f"Bearer {token_b}"},
)

try:
    with urlopen(request, timeout=15) as response:
        print("CROSS-USER ACCESS STATUS:", response.status)
        print("CROSS-USER OWNERSHIP TEST: FAILED")
except HTTPError as exc:
    print("CROSS-USER ACCESS STATUS:", exc.code)
    print(
        "CROSS-USER OWNERSHIP TEST:",
        "PASS" if exc.code == 404 else "FAILED",
    )

# No authentication.
request = Request(
    BASE + f"/analysis/{job_id}",
    method="GET",
)

try:
    with urlopen(request, timeout=15) as response:
        print("UNAUTHENTICATED ACCESS STATUS:", response.status)
        print("UNAUTHENTICATED TEST: FAILED")
except HTTPError as exc:
    print("UNAUTHENTICATED ACCESS STATUS:", exc.code)
    print(
        "UNAUTHENTICATED TEST:",
        "PASS" if exc.code == 401 else "FAILED",
    )
