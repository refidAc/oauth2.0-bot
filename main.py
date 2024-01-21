import base64
import hashlib
import os
import re
import json
import requests
import redis
from requests_oauthlib import OAuth2Session
from flask import Flask, redirect, session, request
import logging


logging.basicConfig(level=logging.INFO)
logging.info("Starting Bot...")
r = redis.from_url(os.environ["REDIS_URL_DOGS"])
for key in r.scan_iter("prefix:*"):
    r.delete(key)
# j_token_str = r.get("save_token")
# print(f"stred tok :: {str(j_token_str)}")
# j_token = json.loads(j_token_str.decode('utf-8'))
# print(j_token)

app = Flask(__name__)
app.secret_key = os.urandom(50)

client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"
redirect_uri = os.environ.get("REDIRECT_URI")

# Set the scopes
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]

# Create a code verifier
code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

# Create a code challenge
code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")

def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def parse_dog_fact():
    url = "http://dog-api.kinduff.com/api/facts"
    dog_fact = requests.request("GET", url).json()
    return dog_fact["facts"][0]

def post_tweet(payload, token):
    print("Tweeting!")
    return requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )

@app.route("/testrefresh", methods=["GET"])
def refresh_token():
    print("Refreshing!")
    t = r.get("token")
    bb_t = t.decode("utf8").replace("'", '"')
    data = json.loads(bb_t)
    # # Prepare the refresh token request parameters
    # params = {
    #     'grant_type': 'refresh_token',
    #     'refresh_token': data["refresh_token"],
    #     'client_id': client_id,
    #     'client_secret': client_secret,
    # }
    # headers = {
    #     'Authorization': 'Bearer {}'.format(data['access_token']),
    #     'Content-Type': 'application/json',
    # }
    
    
    # Encode the client id and secret
    credentials = f'{client_id}:{client_secret}'
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    # Define the headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_credentials}'
    }
    logging.info(f"refresh_token: {data['refresh_token']}")
    # Define the parameters
    params = {
        'grant_type': 'refresh_token',
        'refresh_token': f'{data["refresh_token"]}'
    }

    # Send the POST request
    response = requests.post('https://api.twitter.com/2/oauth2/token', headers=headers, data=params)

    # Parse the response
    #refreshed_token = response.json()
    # Send the refresh token request
    response = requests.post(token_url, params=params, headers=headers)
    print("Status code: ", response.status_code)
    print("Headers: ", response.headers)
    print("Body: ", response.text)
    logging.info(response.status_code)
    logging.info(response.headers)
    logging.info(response.text)

    # Check if the response is not empty and is in JSON format
    if response.status_code == 200:
        try:
            refreshed_token = response.json()
        except ValueError:
            print("Invalid JSON received: ", response.text)
            return {"Error": response.text}
    else:
        print("Unexpected response from server: ", response.text)
        return {"Error": response.text}
    #refreshed_token = response.json()
    print("we refreshed something!")
    if(refreshed_token['error'] or refreshed_token['error']!=None):
        return json.dumps({"Error occured": str(refreshed_token)})
    else:
        st_refreshed_token = '"{}"'.format(refreshed_token)
        j_refreshed_token = json.loads(st_refreshed_token)
        r.set("token", j_refreshed_token)
        return json.dumps({"PreviousToken":str(t),"Token Refreshed?":str(j_refreshed_token)})


@app.route("/")
def demo():
    global twitter
    twitter = make_token()
    authorization_url, state = twitter.authorization_url(
        auth_url, code_challenge=code_challenge, code_challenge_method="S256"
    )
    session["oauth_state"] = state
    return redirect(authorization_url)

@app.route("/oauth/callback", methods=["GET"])
def callback():
    code = request.args.get("code")
    token = twitter.fetch_token(
        token_url=token_url,
        client_secret=client_secret,
        code_verifier=code_verifier,
        code=code,
    )
    raw_t = token
    r.set("raw_token",json.dumps(raw_t))
    st_token = '"{}"'.format(token)
    j_token = json.loads(st_token)
    r.set("token", j_token)
    doggie_fact = parse_dog_fact()
    payload = {"text": "{}".format(doggie_fact)}
    response = post_tweet(payload, token).json()
    return response

# @app.route("/oauth/callback", methods=["GET"])
# def callback():
#     code = request.args.get("code")
#     token = twitter.fetch_token(
#         token_url=token_url,
#         client_secret=client_secret,
#         code_verifier=code_verifier,
#         code=code,
#     )
#     save_token = token
#     save_token = json.dumps(save_token)
#     r.set("save_token", save_token)
#     st_token = '"{}"'.format(token)
#     j_token = json.loads(st_token)
#     r.set("token", j_token)
#     doggie_fact = parse_dog_fact()
#     payload = {"text": "{}".format(doggie_fact)}
#     response = post_tweet(payload, token).json()
#     return response


if __name__ == "__main__":
    app.run()
    