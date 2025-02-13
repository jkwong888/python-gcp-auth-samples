from os import chmod
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import json
import requests
import time

import google.auth
import google.auth.transport.requests
import google.oauth2.id_token

# generate a private key

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print("\n".join([s.decode("utf-8") for s in pem.splitlines()]))

# get the public bytes
pub_key = private_key.public_key()
p = pub_key.public_bytes(
    encoding = serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)
pub_key_str = p.decode("utf-8")


# call GCP
creds, project = google.auth.default(scopes="https://googleapis.com/auth/cloud-platform")
auth_req = google.auth.transport.requests.Request()
#id_token = google.oauth2.id_token.fetch_id_token(auth_req,)
creds.refresh(auth_req)

print(creds.valid)
print(creds.id_token)
print(creds.token)

userEmail = "jkwong@jkwng.altostrat.com"
exp_duration_usec = 300 * 1000 * 1000 # 5 minutes
expirationTime = round((time.time() * 1000 * 1000) + exp_duration_usec)
req_payload = {
    "key": f"{pub_key_str} {userEmail}",
    "expirationTimeUsec": f"{expirationTime}"
}

print(json.dumps(req_payload))

# response = requests.get(
#     url=f"https://compute.googleapis.com/compute/v1/projects/jkwng-factory/zones/northamerica-northeast2-a/instances",
#     headers={
#         "Authorization": f"Bearer {creds.token}"

#     }
# )
# print(f"{response.status_code} {response.reason} {response.json()}")
os_login_url = f"https://oslogin.googleapis.com/v1/users/{userEmail}:importSshPublicKey"
print(os_login_url)

response = requests.post(
    url=os_login_url,
    data=json.dumps(req_payload),
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {creds.token}"
    }
)

print(f"{response.status_code} {response.reason} {response.text}")