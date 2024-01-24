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
from urllib.parse import urlencode, urlsplit
from opensea_sdk import *
import tweepy
from datetime import datetime
from vrtools.vrutil import *
from requests.auth import HTTPBasicAuth
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import io
from PIL import Image
import cairosvg
logging.basicConfig(level=logging.INFO)
logging.info("Starting Bot...")
global r
r = redis.from_url(os.environ["REDIS_URL_DOGS"])
# for key in r.scan_iter("prefix:*"):
#     r.delete(key)
# j_token_str = r.get("save_token")
# print(f"stred tok :: {str(j_token_str)}")
# j_token = json.loads(j_token_str.decode('utf-8'))
# print(j_token)


#####OPENSEA CONFIG############
# def run_opensea_stream_client():
    
#     logging.basicConfig(level=logging.INFO)
#     logging.error("Starting opensea client loop...")
#     print("inside run opensea stream")
#     opensea_api_key=os.environ.get("OPENSEA_KEY")
#     collection_slug=['nuclear-nerds-of-the-accidental-apocalypse','pudgypenguins','cryptopunks','coqvshunter']
#     print('attempting to connect to redis')
#     r = redis.from_url(os.environ["REDIS_URL_DOGS"])
#     print('connected to redis')
#     global count
#     count = 0
#     def handle_item_sold(payload: dict):
#         logging.info(f"Event Handled ::::{payload}")
#         payload = json.loads(r.get("single_message_test"))
#         print(f"Event Handled ::::{payload}")
#         # Fetch the access token from Redis
#         t = r.get("token")
#         bb_t = t.decode("utf8").replace("'", '"')
#         data = json.loads(bb_t)
#         # Extract the image URL and price from the payload
#         image_url = payload['payload']['item']['metadata']['image_url']
#         price = payload['payload']['base_price']
#         price = convert_to_ether(price)
#         r.set("app_verify","true")
            
#     def handle_events(payload: dict):
#         logging.error(f"Event Handled ::::{payload}")
#         # Get current date
#         # payload.collection.slug
#         slug=payload['payload']['collection']['slug']
#         # print("====================================================")
#         # print(slug)
#         # print("====================================================")
#         # print(payload)
#         event_type=payload['event_type']
#         key=slug+"_"+event_type
#         collect_statistics(key)
#         print(f'slug_event:: {key}',flush=True)
#         logging.error('slug_event:: {key}')
#         if key == 'nuclear-nerds-of-the-accidental-apocalypse_item_sold':
#             resp = event_sold_handler(payload)
#             logging.error(f'finished handling sold event for :: {payload}')
#         if slug == 'nuclear-nerds-of-the-accidental-apocalypse':
#             rSet('saved_nerd_sold', payload)
#         if event_type == 'item_sold':
#             rSet('saved_any_sold', payload)
        
#     def event_sold_handler(payload:dict):
#         logging.info(f"Event Handled ::::{payload}")
#         payload = json.loads(r.get("single_message_test"))
#         print(f"Event Handled ::::{payload}")
#         # Fetch the access token from Redis
#         data = loadToken()
#         # Extract the image URL and price from the payload
#         image_url = payload['payload']['item']['metadata']['image_url']
#         media_id=download_upload_media(image_url)
#         price = payload['payload']['base_price']
#         price = convert_to_ether(price)
#         tweet_text = f"Test! with image! Price: {price} WETH"
#         # Prepare the payload for the tweet
#         #time.sleep(3)
#         payload = {"text": tweet_text, "attachments": {"media_keys": [media_id]}}
#         #payload = {"text": tweet_text}
#         #Post the tweet
#         print("TWEETING!")
#         response = post_tweet(payload, data).json()
#         #print(response)
#         return response
    
#     def collect_statistics(slug_event_type:str):
#         print('entered collect stats')
#         now = datetime.now()
#         # Create keys for today and this month
#         today = f"{slug_event_type}_{now.year}-{now.month}-{now.day}"
#         this_month = f"{slug_event_type}_{now.year}-{now.month}"
#         # Increment counters
#         r.incr(today)
#         r.incr(this_month)

#     print("Started opensea")
#     Client = OpenseaStreamClient(opensea_api_key, Network.MAINNET)
#     Client.onEvents(
#         collection_slug,
#         [EventTypes.ITEM_RECEIVED_OFFER, EventTypes.ITEM_RECEIVED_BID, EventTypes.ITEM_SOLD],
#         handle_events
#         )
#     Client.startListening()
    
#        [EventTypes.ITEM_RECEIVED_OFFER, EventTypes.ITEM_TRANSFERRED, EventTypes.ITEM_CANCELLED, EventTypes.ITEM_LISTED, EventTypes.ITEM_METADATA_UPDATED, EventTypes.ITEM_RECEIVED_BID, EventTypes.ITEM_TRANSFERRED, EventTypes.ITEM_SOLD],

#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################
#########################################################################################################################################################################################################################


app = Flask(__name__)
#auth = HTTPBasicAuth()
app.secret_key = os.urandom(50)
client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"
redirect_uri = os.environ.get("REDIRECT_URI")

# Set the scopes
scopes = ["tweet.read", "tweet.write", "users.read", "offline.access"]
# Create a code verifier
code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

# Create a code challenge
code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")
c_username = os.environ.get("C_USERNAME")
c_password = os.environ.get("C_PASSWORD")

users = {
    f'{c_username}': generate_password_hash(f'{c_password}')
}
basic_auth = HTTPBasicAuth(client_id, client_secret)

def extract_sold_item_info(payload:dict):
    
    retDict = {}
    temp = payload['payload']
    sale_price_str = temp['sale_price']
    usd_price_str = temp['payment_token']['usd_price']

    # Convert the sale price and USD price to float
    sale_price = float(sale_price_str) / 1e18
    usd_price = float(usd_price_str)

    # Calculate the total sale price in USD
    total_usd = sale_price * usd_price

    # Format the total sale price with comma separation and two decimal places
    formatted_usd = "{:,.2f}".format(total_usd)

    retDict['chain']=temp['chain']
    retDict['from_address']=temp['maker']['address']
    retDict['to_address']=temp['taker']['address']
    #payload.item.metadata.image_url
    retDict['image_url']=temp['item']['metadata']['image_url']
    retDict['nft_name']=temp['item']['metadata']['name']
    retDict['nft_link']=temp['item']['permalink']
    retDict['amount_symbol'] = temp['payment_token']['symbol']
    retDict['amount_token'] = int(temp['sale_price']) / (10 ** int(temp['payment_token']['decimals']))
    retDict['amount_usd'] = formatted_usd
    retDict['encoded_nft_link'] = base64.urlsafe_b64encode(retDict['nft_link'].encode()).decode()
    return retDict

def loadToken():
    t = r.get("token")
    bb_t = t.decode("utf8").replace("'", '"')
    jtoken = json.loads(bb_t)
    return jtoken

def saveToken(token):
    st_token = '"{}"'.format(token)
    j_token = json.loads(st_token)
    r.set("token", j_token)
    
def rGet(key):
    return json.loads(r.get(key))

def rSet(key,value):
    return r.set(key,json.dumps(value))


@basic_auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

@app.route('/echo', methods=['POST'])
@basic_auth.login_required
def echo():
    data = request.get_json()
    return json.dumps(data), 200
    
@app.route('/wakeup', methods=['GET'])
def wakeup():
    print('im awake!')
    return json.dumps({"i'm": "awake"})


def download_image(url):
    response = requests.get(url, stream=True)
    response.raise_for_status()
    image = Image.open(io.BytesIO(response.content))
    return image

def convert_to_jpg(image):
    converted_image = image.convert('RGB')
    return converted_image

def download_upload_media(url):
    #download
    #reformat width
    #url = 'https://i.seadn.io/gcs/files/e3a2 s744c538cb97625d93967425b24d4.png?w=500&auto=format'
# Parse the URL
    parsed_url = urlparse(url)
    # Get the file extension
    file_extension = os.path.splitext(parsed_url.path)[1]
    # Check if the file extension is .svg
    print(f'file extension:::::::{file_extension}')
    filename=''
    if file_extension == ".svg":
        # Download the SVG file
        response = requests.get(parsed_url.geturl())
        # Convert SVG to PNG using cairosvg
        png_data = cairosvg.svg2png(bytestring=response.content)
        # Open the PNG image data with PIL
        image = Image.open(io.BytesIO(png_data))
        # Save the image in JPG format
        image.save("temp.jpg")
        filename='temp.jpg'
    else:
        print("File is not an SVG.")
        image = download_image(url)
        jpg_image = convert_to_jpg(image)
        filename='temp.jpg'
        jpg_image.save(filename)
    #upload
    tweepy_auth = tweepy.OAuth1UserHandler(
        "{}".format(os.environ.get("API_KEY")),
        "{}".format(os.environ.get("API_SECRET")),
        "{}".format(os.environ.get("ACCESS_TOKEN")),
        "{}".format(os.environ.get("ACCESS_TOKEN_SECRET")),
    )
    tweepy_api = tweepy.API(tweepy_auth)
    post = tweepy_api.simple_upload(filename)
    text = str(post)
    media_id = re.search("media_id=(.+?),", text).group(1)
    payload = {"media": {"media_ids": ["{}".format(media_id)]}}
    print(f"media_payload :: {payload}")
    os.remove(filename)
    return payload['media']['media_ids']

def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

def parse_dog_fact():
    url = "http://dog-api.kinduff.com/api/facts"
    dog_fact = requests.request("GET", url).json()
    return dog_fact["facts"][0]

@app.route("/retweet", methods=["GET"])
def retweet():
    data=loadToken()
    doggie_fact = parse_dog_fact()
    payload = {"text": "{}".format(doggie_fact)}
    response = post_tweet(payload, data).json()
    return response

# @app.route('/simulateSoldEvent', methods=['GET'])
# def simulateEvent():
#     payload = rGet("saved_nerd_item_sold")
#     logging.info(f"Event Handled ::::{payload}")
#     app.logger.info(f"Event Handled ::::{payload}")
#     print(f"Event Handled ::::{payload}")
#     # Fetch the access token from Redis
#     #reauth()
#     data = loadToken()
#     # Extract the image URL and price from the payload
#     metadata = extract_sold_item_info(payload)
#     image_url = metadata['image_url']
#     media_id = None
#     if image_url != None:
#         media_id=download_upload_media(image_url)
#     # price = payload['payload']['base_price']
#     tweet_text = "{} bought for {} {} (${} USD) by {} from {} {}".format(
#         metadata['nft_name'],
#         metadata['amount_token'],
#         metadata['amount_symbol'],
#         metadata['amount_usd'],
#         metadata['from_address'][:8],
#         metadata['to_address'][:8],
#         metadata['nft_link']
#     )
#     print(tweet_text)
#     # Prepare the payload for the tweet
#     #time.sleep(3)
#     if media_id != None:
#         payload = {"text": tweet_text, "media": {"media_ids": media_id}}
#     else:
#         payload = {"text": tweet_text}
#     #Post the tweet
#     print("TWEETING!")
#     response = post_tweet(payload, data).json()
#     Logger(f"response from tweeting {response}").error()
#     Logger(f"response from tweeting full ::: {response}").error()
#     #print(response)
#     return response

@app.route("/eventSoldHandler", methods=["POST"])
@basic_auth.login_required
def event_sold_handler():
    
    payload = request.get_json()
    logging.info(f"Event Handled ::::{payload}")
    app.logger.info(f"Event Handled ::::{payload}")
    print(f"Event Handled ::::{payload}")
    # Fetch the access token from Redis
    #reauth()
    data = loadToken()
    # Extract the image URL and price from the payload
    metadata = extract_sold_item_info(payload)
    image_url = metadata['image_url']
    media_id = None
    if image_url != None:
        media_id=download_upload_media(image_url)
    # price = payload['payload']['base_price']
    tweet_text = "{} bought for {} {} (${} USD) by {} from {} {}".format(
        metadata['nft_name'],
        metadata['amount_token'],
        metadata['amount_symbol'],
        metadata['amount_usd'],
        metadata['from_address'][:8],
        metadata['to_address'][:8],
        metadata['nft_link']
    )
    print(tweet_text)
    # Prepare the payload for the tweet
    #time.sleep(3)
    if media_id != None:
        payload = {"text": tweet_text, "media": {"media_ids": media_id}}
    else:
        payload = {"text": tweet_text}
    #Post the tweet
    print("TWEETING!")
    response = post_tweet(payload, data).json()
    Logger(f"response from tweeting {response}").error()
    Logger(f"response from tweeting full ::: {response}").error()
    #print(response)
    return response

# def post_tweet(payload, aToken):
#     print("Tweeting!")
    
#     return requests.request(
#         "POST",
#         "https://api.twitter.com/2/tweets",
#         json=payload,
#         headers={
#             "Authorization": "Bearer {}".format(aToken["access_token"]),
#             "Content-Type": "application/json",
#         },
#     )

def post_tweet(payload, aToken):
    now = datetime.now()
    # Check if the 'last_tweet_time' is stored in the Redis database
    if r.exists('last_tweet_time'):
        # If it is, get the last tweet time
        last_tweet_time = datetime.fromtimestamp(float(r.get('last_tweet_time')))
        # If less than 1 minute have passed since the last tweet, return without sending the tweet
        if (now - last_tweet_time).total_seconds() < 60:
            print("Only 1 minute has passed since the last tweet.")
            app.logger.info("Only 1 minute has passed since the last tweet")
            Logger("Only 1 minute has passed since the last tweet").error()
            logging.error("Only 1 min passed")
            return
    # Send the tweet
    print("Tweeting!")
    response = requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(aToken["access_token"]),
            "Content-Type": "application/json",
        },
    )
    # If the request was successful, update the 'last_tweet_time' in the Redis database
    r.set('last_tweet_time', now.timestamp())

    return response

@app.route("/testrefresh", methods=["GET"])
def refresh_token():
    print("Refreshing!")
    # t = r.get("token")
    # bb_t = t.decode("utf8").replace("'", '"')
    # data = json.loads(bb_t)
    data=loadToken()
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
    print(f"data_token:::: {data}")
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_credentials}',
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
    r.set("req_code",code)
    token = twitter.fetch_token(
        token_url=token_url,
        client_secret=client_secret,
        code_verifier=code_verifier,
        code=code,
    )
    raw_token = token
    rSet("raw_token",raw_token)
    saveToken(token)
    # doggie_fact = parse_dog_fact()
    # payload = {"text": "{}".format(doggie_fact)}
    response = {"Success": "Authed!"}
    return json.dumps(response)

#@app.route("/oauth/callback", methods=["GET"])
# def callback():
#     code = request.args.get("code")
#     token = twitter.fetch_token(
#         token_url=token_url,
#         client_secret=client_secret,
#         code_verifier=code_verifier,
#         code=code,
#     )
#     user_me = requests.request(
#         "GET",
#         "https://api.twitter.com/2/users/me",
#         headers={"Authorization": "Bearer {}".format(token["access_token"])},
#     ).json()
#     print(user_me)
#     user_id = user_me["data"]["id"]
#     tokens = {"new_token": token}
#     t = tokens["new_token"]
#     refreshed_token = twitter.refresh_token(
#           client_id=client_id,
#           client_secret=client_secret,
#           token_url=token_url,
#           refresh_token=t["refresh_token"],
#         )
#     tokens.update({"new_token": refreshed_token})
#     return "You should now have a refreshed token"

@app.route("/test/reauth", methods=["GET"])
def reauth():
    app.logger.info("in reauth!")
    #code = request.args.get("code")
    code=r.get('req_code')
    # token = twitter.fetch_token(
    #     token_url=token_url,
    #     client_secret=client_secret,
    #     code_verifier=code_verifier,
    #     code=code,
    # )
    
    token = twitter.refresh_token(
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        include_client_id=True,
        code_verifier=code_verifier,
    )
    raw_t = token
    rSet("raw_token",raw_t)
    saveToken(token)
    return json.dumps({'I':'Reauthed'})

# def run_flask_server():
#     #refresh_token()
#     app.run()

if __name__ == '__main__':
    # p1 = Process(target=run_opensea_stream_client)
    app.run()
    # p1.start()
    # p2.start()
    # p1.join()
    # p2.join()
