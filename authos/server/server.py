#!/usr/bin/env python3

import logging
import os
import re
import requests
import subprocess
import sys

from bottle import request, route, run, template
from oauthlib.oauth2 import WebApplicationClient

'''
I use this Auth0 identity for other things and I would rather not
have its details publish its connection info on GitHub, so some stuff is
redacted. I apologize for any inconvenience.
'''

# set up logger
logging.basicConfig(encoding="UTF-8", level=logging.INFO)

# authenticate user
client_id = "<redacted>"
client_secret = "<redacted>"
client = WebApplicationClient(client_id)

authorization_url = "https://<redacted>.eu.auth0.com/authorize"
token_url = "https://<redacted>.eu.auth0.com/oauth/token"
redirect_url = "http://localhost:1337/callback"
userinfo_url = "https://<redacted>.eu.auth0.com/userinfo"

url = client.prepare_request_uri(
  authorization_url,
  redirect_uri = redirect_url,
  scope = ["read:user"],
)

process = subprocess.Popen(["xdg-open", url], user="aadhi")

@route('/callback')
def index():
    data = {
        "grant_type": "authorization_code",
        "code": request.query["code"],
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_url
    }
    response = requests.post(token_url, data=data)
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(userinfo_url, headers=headers)
    
    role = response.json()["https://localhost:1337/groups"][0]

    logging.info("loading policy into kernel")

    policy = []
    parser = re.compile(r"^([/a-zA-Z\.\_0-9]+)\s\[([\w\,]+)\]\s?([rwx]*)\s*$");
    with open(sys.argv[1]) as policyFile:
        for idx, line in enumerate(policyFile.readlines()):
            try:
                groups = parser.match(line).groups()
            except AttributeError as e:
                logging.error("malformed policy on line " + str(idx + 1))
                exit()

            permissions = 0
            permissions |= (1 << 2) if 'r' in groups[2] else 0
            permissions |= (1 << 1) if 'w' in groups[2] else 0
            permissions |= (1 << 0) if 'x' in groups[2] else 0
            policy.append((groups[0], groups[1], permissions))

    policyStr = ""
    for policyEntry in policy:
        if policyEntry[1] == role:
            policyStr += f"{policyEntry[0]}\0{policyEntry[2]}\0"

    if not os.path.exists("/dev/authos_policy"):
        logging.error("authos kernel module not loaded")
        exit()

    with open("/dev/authos_policy", "wb") as deviceFile:
        deviceFile.write(policyStr.encode("UTF-8"))
        deviceFile.flush()

    logging.info("kernel policy updated")

    return "User authenticated and AuthOS policy updated. You may close this page."

run(host='localhost', port=1337)
