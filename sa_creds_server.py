from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import requests
import json
import jwt
from cryptography.x509 import load_pem_x509_certificate


app = FastAPI()

sa_email = "test-sa@jkwng-factory.iam.gserviceaccount.com"
cert_url = f"https://www.googleapis.com/service_accounts/v1/jwk/{sa_email}"
aud = "my-service"

def validate_jwt(signed_jwt: str):
    # get the jwt header to know which key and algorithm to use to verify
    jwt_header = jwt.get_unverified_header(signed_jwt)
    #print(jwt_header)

    cert_url = f"https://www.googleapis.com/service_accounts/v1/metadata/x509/{sa_email}"

    # get the x509 cert to verify
    cert_resp = requests.get(
        url=cert_url
    )

    cert_map = json.loads(cert_resp.text)

    alg = jwt_header['alg']
    kid = jwt_header['kid']

    # try to validate the signed JWT using the public key inside cert
    if kid not in cert_map:
        print("keyid not found")
        raise Exception("keyid not found")

    cert_str = cert_map[kid]
    cert_obj = load_pem_x509_certificate(bytes(cert_str, 'utf-8'))
    public_key = cert_obj.public_key()

    #print(public_key)
    try:
        r = jwt.decode(signed_jwt, 
                    public_key, 
                    issuer=sa_email,
                    audience=[aud], 
                    algorithms=[alg])
        return r 
    except Exception as e:
        #print(e)
        raise e



@app.middleware("http")
async def check_auth_header(request: Request, call_next):

    # check if the authorization header exists
    if 'Authorization' not in request.headers:
        return JSONResponse(content={"message": "Authorization token not found"}, status_code=status.HTTP_401_UNAUTHORIZED)
    
    header_val = request.headers['Authorization']
    #print(header_val)
    if not header_val.lower().startswith('bearer '):
        return JSONResponse(content={"message": "Bearer token not found"}, status_code=status.HTTP_401_UNAUTHORIZED)
    
    signed_jwt = header_val[len('bearer '):]

    try:
        claims = validate_jwt(signed_jwt)

        if claims['sub'] != sa_email:
            raise Exception("Invalid subject")
    except Exception as e:
        return JSONResponse(content={"message": f"{e}"}, status_code=status.HTTP_401_UNAUTHORIZED)

    response = await call_next(request)

    return response


@app.get("/")
async def hello():
    return {"message": "Hello World"}
