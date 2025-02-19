import requests
import json
import time

from datetime import datetime, timezone, timedelta

import google.auth
import google.auth.transport.requests
import google.oauth2.id_token

sa_email = "test-sa@jkwng-factory.iam.gserviceaccount.com"
aud = "my-service"

# authenticate GCP
creds, project = google.auth.default(scopes="https://googleapis.com/auth/cloud-platform")
auth_req = google.auth.transport.requests.Request()

creds.refresh(auth_req)# generate the JWT using this REST API call
sa_creds_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:signJwt"

def getToken(aud=aud, sub=sa_email):
    # generate a JWT to be signed
    jwt_payload = {
        "iss": sa_email,
        "sub": sub,
        "aud": aud,
        "iat": round((datetime.now(tz=timezone.utc)).timestamp()),
        "exp": round((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    }

    req_payload = {
        "payload": json.dumps(jwt_payload),
    }

    response = requests.post(
        url=sa_creds_url,
        data=json.dumps(req_payload),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {creds.token}"
        }
    )

    signed_jwt = response.json()['signedJwt']

    return signed_jwt

service_url = "http://localhost:8000/"
token = getToken()
time.sleep(1)

# test 1: happy path
response = requests.get(
    url=service_url,
    headers={
        "Authorization": f"Bearer {token}"
    }
)

print(f"good: {response.status_code} {response.reason} {response.text}")

# test 2: no token
response = requests.get(
    url=service_url,
)

print(f"no token: {response.status_code} {response.reason} {response.text}")

# test 3: not bearer token
response = requests.get(
    url=service_url,
    headers={
        "Authorization": f"adsdfsd"
    }
)

print(f"not bearer token: {response.status_code} {response.reason} {response.text}")

# test 3: invalid token
response = requests.get(
    url=service_url,
    headers={
        "Authorization": f"Bearer adsdfsd"
    }
)

print(f"invalid bearer token: {response.status_code} {response.reason} {response.text}")

bad_sub_token = getToken(sub="asdf@asdf.com")
time.sleep(1)
response = requests.get(
    url=service_url,
    headers={
        "Authorization": f"Bearer {bad_sub_token}"
    }
)

print(f"invalid subject: {response.status_code} {response.reason} {response.text}")



bad_aud_token = getToken(aud="bad-service")

time.sleep(1)
response = requests.get(
    url=service_url,
    headers={
        "Authorization": f"Bearer {bad_aud_token}"
    }
)

print(f"invalid audience: {response.status_code} {response.reason} {response.text}")