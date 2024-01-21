import base64
import hashlib
import os
import re
import json
import requests
import redis
from requests_oauthlib import OAuth2Session
from flask import Flask, redirect, session, request
from datetime import datetime

r = redis.from_url(os.environ["REDIS_URL_DOGS"])
r.delete('token')
app = Flask(__name__)
app.secret_key = os.urandom(50)
client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"
redirect_uri = os.environ.get("REDIRECT_URI")
# Set the scopes
scopes = ["tweet.write","offline.access"]
# Create a code verifier
code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
# Create a code challenge
code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")

def refresh_token():
    # Get the refresh token from Redis
    t = r.get("token")
    bb_t = t.decode("utf8").replace("'", '"')
    data = json.loads(bb_t)

    # Use the refresh token to get a new access token
    refreshed_token = twitter.refresh_token(
        client_id=client_id,
        client_secret=client_secret,
        token_url=token_url,
        refresh_token=data["refresh_token"],
    )

    # Save the new access token to Redis
    st_refreshed_token = '"{}"'.format(refreshed_token)
    j_refreshed_token = json.loads(st_refreshed_token)
    r.set("token", j_refreshed_token)

def logPrint(name=None, text=None):
    if name is not None:
        print(f'{name} :: {text}')
    else:
        print(f'{text}')

# Retrieve the token from Redis
def loadAuthToken():
    j_token_str = r.get("token")
    j_token = json.loads(j_token_str.decode())
    return j_token

def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def parse_dog_fact():
    url = "http://dog-api.kinduff.com/api/facts"
    dog_fact = requests.request("GET", url).json()
    return dog_fact["facts"][0]


def post_tweet(payload):
    print("Tweeting!")
    # Load the token from Redis
    token = loadAuthToken()
    # Check if the token has expired
    if token['expires_at'] <= datetime.now().timestamp():
        # If the token has expired, refresh it
        refresh_token()
        # Reload the token from Redis
        token = loadAuthToken()
    # Make the request with the token
    return requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )
@app.route("/")
def demo():
    # Try to load the token from Redis
    try:
        token = loadAuthToken()
        doggie_fact = parse_dog_fact()
        payload = {"text": "{}".format(doggie_fact)}
        response = post_tweet(payload, token).json()
        return response
    except Exception:
        # If loading the token fails (e.g., it doesn't exist or has expired), start the OAuth flow
        global twitter
        twitter = make_token()
        authorization_url, state = twitter.authorization_url(
            auth_url, code_challenge=code_challenge, code_challenge_method="S256"
        )
        session["oauth_state"] = state
        return redirect(authorization_url)


@app.route("/oauth/callback", methods=["GET"])
def callback():
    name = 'callback()'
    code = request.args.get("code")
    token = twitter.fetch_token(
        token_url=token_url,
        client_secret=client_secret,
        code_verifier=code_verifier,
        code=code,
    )
    logPrint(name, f"")
    st_token = '"{}"'.format(token)
    j_token = json.loads(st_token)
    r.set("token", j_token)
    doggie_fact = parse_dog_fact()
    payload = {"text": "{}".format(doggie_fact)}
    response = post_tweet(payload).json()
    return response


if __name__ == "__main__":
    app.run()
