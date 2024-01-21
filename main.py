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
from urllib.parse import urlencode
from opensea_sdk import *
import threading
import asyncio
import inspect
from multiprocessing import Process

logging.basicConfig(level=logging.INFO)
logging.info("Starting Bot...")
r = redis.from_url(os.environ["REDIS_URL_DOGS"])
for key in r.scan_iter("prefix:*"):
    r.delete(key)
# j_token_str = r.get("save_token")
# print(f"stred tok :: {str(j_token_str)}")
# j_token = json.loads(j_token_str.decode('utf-8'))
# print(j_token)


#####OPENSEA CONFIG############
def run_opensea_stream_client():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting opensea client loop...")
    opensea_api_key=os.environ.get("OPENSEA_KEY")
    collection_slug=['nuclear-nerds-of-the-accidental-apocalypse','pudgypenguins']
    global count
    count=0
    r = redis.from_url(os.environ["REDIS_URL_DOGS"])
    # def handle_item_sold(payload: dict):
    #     logging.info(f"Event Handled ::::{payload}")
    #     if count==0:
    #         r.set("single_message_test",json.dumps(payload))
    #         count=count+1
    #     print(f"Event Handled ::::{payload}")
    def handle_item_sold(payload: dict):
        logging.info(f"Event Handled ::::{payload}")
        if count==0:
            payload = json.loads(r.get("single_message_test"))
            print(f"Event Handled ::::{payload}")
            # Fetch the access token from Redis
            t = r.get("token")
            bb_t = t.decode("utf8").replace("'", '"')
            data = json.loads(bb_t)
            # Extract the image URL and price from the payload
            #payload.item.metadata.image_url
            image_url = payload['payload']['item']['metadata']['image_url']
            price = payload['payload']['base_price']
            price = convert_to_ether(price)
            # Prepare the tweet text
            tweet_text = f"Test! Price: {price} WETH\n![Image]({image_url})"
            # Prepare the payload for the tweet
            payload = {"status": tweet_text}
            # Post the tweet
            response = post_tweet(payload, data).json()
            count=count+1
        print(response)
        
    def convert_to_ether(amt):
        #bid_wei = int("19416600000000000000")
        bid_wei = int(amt)
        bid_ether = bid_wei / (10 ** 18)
        logging.info(bid_ether)
        return bid_ether
    print("Started opensea")
    Client = OpenseaStreamClient(opensea_api_key, Network.MAINNET)
    Client.onEvents(
        collection_slug,
        [EventTypes.ITEM_RECEIVED_OFFER, EventTypes.ITEM_TRANSFERRED, EventTypes.ITEM_CANCELLED, EventTypes.ITEM_LISTED, EventTypes.ITEM_METADATA_UPDATED, EventTypes.ITEM_RECEIVED_BID, EventTypes.ITEM_TRANSFERRED, EventTypes.ITEM_SOLD],
        handle_item_sold
        )
    Client.startListening()
###############################

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


def run_stream_client():
    stream_client = OpenSeaStreamClient()
    stream_client.run()
    
def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def parse_dog_fact():
    url = "http://dog-api.kinduff.com/api/facts"
    dog_fact = requests.request("GET", url).json()
    return dog_fact["facts"][0]

@app.route("/retweet", methods=["GET"])
def retweet():
    t = r.get("token")
    bb_t = t.decode("utf8").replace("'", '"')
    data = json.loads(bb_t)
    doggie_fact = parse_dog_fact()
    payload = {"text": "{}".format(doggie_fact)}
    response = post_tweet(payload, data).json()
    return response

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
    credentials = f"{client_id}:{client_secret}"
    logging.info(f"credentials :: {credentials}")
    encoded_credentials = base64.urlsafe_b64encode(credentials.encode()).decode()
    logging.info(f"encoded creds : {encoded_credentials}")
    # Define the headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_credentials}',
        'grant_type': 'refresh_token'
    }
    logging.info(f"req headers: {headers}")
    # Define the parameters
    params = {
        'grant_type': 'refresh_token',
        'refresh_token': f'{data["refresh_token"]}'
    }
    #params = 'grant_type=refresh_token&refresh_token=' + f'{data["refresh_token"]}'
    params = urlencode(params)
    # Convert the parameters to a JSON string
    
    logging.info(f"req params: {params}")

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

def reauth():
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
    return token



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

def run_flask_server():
    app.run()

if __name__ == '__main__':
    p1 = Process(target=run_opensea_stream_client)
    p2 = Process(target=run_flask_server)
    p1.start()
    p2.start()
    p1.join()
    p2.join()
