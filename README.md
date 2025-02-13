# Python GCP authentication samples


## Service Account Credentials authentication

1. Create a service account (e.g. `test-sa`) - the email address in my case: `test-sa@jkwng-factory.iam.gserviceaccount.com`.
2. Give users/groups the `Service Account Token Creator` role on the service account:
   
   ```
   $ gcloud iam service-accounts add-iam-policy-binding test-sa@jkwng-factory.iam.gserviceaccount.com --member=user:jkwong@jkwng.altostrat.com --role=roles/iam.serviceAccountTokenCreator
   ```

the currently authenticated user is used to request the JWT.  for example, `gcloud auth login` will show me my local user, or if you're running this code inside of Google Cloud, it will use Application Default Credentials retrieved from the metadata server.

in the client code [sa_creds_client.py](sa_creds_client.py), it will use the Service Account Credentials API to sign a JWT using the service account's private key (stored in Google Cloud).  We then call our API passing this token.

on the server side [sa_creds_server.py](sa_creds_server.py), a middleware will retrieve the x509 cert and verify the token was signed using the attached public key.  if it was not, fail authentication.  if authentication is successful, then call the route code.  Note that the x509 cert can be cached for up to 24 hours so you do not need to retrieve it for every request, but you should refresh it every so often.


you can start the server in dev mode using uvicorn:

```
uvicorn sa_creds_server:app
```


# OS login SSH

[os_login_ssh.py](os_login_ssh.py) will generate an SSH key pair for your currently logged in user and add it to its OS login profile.  we can then programatically SSH into a GCE VM using the key.  

I abandoned this one because i wasn't sure whether dynamically running SSH commands is that great of an idea.


# python-gcp-auth-samples
