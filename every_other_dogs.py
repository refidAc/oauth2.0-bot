import main
from vrtools.vrutil import *
import json
import os
import base64
import requests
import main 
import json
import os
import redis

twitter = main.make_token()
client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
token_url = "https://api.twitter.com/2/oauth2/token"

r = redis.from_url(os.environ["REDIS_URL_DOGS"])

# Get all keys
keys = r.keys()

# Initialize an empty dictionary to hold the values
all_values = {}
print(keys)
# Iterate over all keys
for key in keys:
    print((key))
    key=key.decode('utf-8')
    # Get the value associated with the key
    value = r.get(str(key))
    value_str = value.decode('utf-8')
    print(value_str)
    all_values[key] = value

# Print all values
print(json.dumps(all_values, indent=4))
# testpayload={
#     "event_type": "item_received_bid",
#     "payload": {
#         "base_price": "18000000000000000000",
#         "chain": "ethereum",
#         "collection": {
#             "slug": "pudgypenguins"
#         },
#         "created_date": "2024-01-22T06:16:15.000000+00:00",
#         "event_timestamp": "2024-01-22T06:16:20.121651+00:00",
#         "expiration_date": "2024-01-22T06:41:15.000000+00:00",
#         "item": {
#             "chain": {
#                 "name": "ethereum"
#             },
#             "metadata": {
#                 "animation_url": None,
#                 "image_url": "https://i.seadn.io/gcs/files/70abb7b389084ab27ae199e284bbcdba.png?w=500&auto=format",
#                 "metadata_url": "ipfs://bafybeibc5sgo2plmjkq2tzmhrn54bk3crhnc23zd2msg4ea7a4pxrkgfna/3246",
#                 "name": "Pudgy Penguin #3246"
#             },
#             "nft_id": "ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/3246",
#             "permalink": "https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/3246"
#         },
#         "maker": {
#             "address": "0xb73d5c81096da0f0d16741d1dc89e96a054920b2"
#         },
#         "order_hash": "0x18ea513382e2c8e9307cd0cfd1a595556205cc94992accdaf71e77f21cad1d4c",
#         "payment_token": {
#             "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
#             "decimals": 18,
#             "eth_price": "1.000000000000000",
#             "name": "Wrapped Ether",
#             "symbol": "WETH",
#             "usd_price": "2420.690000000000055000"
#         },
#         "protocol_address": "0x00000000000000adc04c56bf30ac9d3c0aaf14dc",
#         "protocol_data": {
#             "parameters": {
#                 "conduitKey": "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000",
#                 "consideration": [
#                     {
#                         "endAmount": "1",
#                         "identifierOrCriteria": "3246",
#                         "itemType": 2,
#                         "recipient": "0xb73d5c81096DA0f0d16741D1Dc89e96A054920b2",
#                         "startAmount": "1",
#                         "token": "0xBd3531dA5CF5857e7CfAA92426877b022e612cf8"
#                     },
#                     {
#                         "endAmount": "450000000000000000",
#                         "identifierOrCriteria": "0",
#                         "itemType": 1,
#                         "recipient": "0x0000a26b00c1F0DF003000390027140000fAa719",
#                         "startAmount": "450000000000000000",
#                         "token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
#                     },
#                     {
#                         "endAmount": "90000000000000000",
#                         "identifierOrCriteria": "0",
#                         "itemType": 1,
#                         "recipient": "0x1AFa64e9B8e3090F2001F66D9c9a74cde646738a",
#                         "startAmount": "90000000000000000",
#                         "token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
#                     }
#                 ],
#                 "counter": "0xe395a8f46f5e3084b96035e069e5a5b2",
#                 "endTime": "1705905675",
#                 "offer": [
#                     {
#                         "endAmount": "18000000000000000000",
#                         "identifierOrCriteria": "0",
#                         "itemType": 1,
#                         "startAmount": "18000000000000000000",
#                         "token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
#                     }
#                 ],
#                 "offerer": "0xb73d5c81096da0f0d16741d1dc89e96a054920b2",
#                 "orderType": 1,
#                 "salt": "0xc47304a88c2d764fb82a6510f6095d8b",
#                 "startTime": "1705904175",
#                 "totalOriginalConsiderationItems": 3,
#                 "zone": "0x0000000000000000000000000000000000000000",
#                 "zoneHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
#             },
#             "signature": None
#         },
#         "quantity": 1,
#         "taker": None
#     },
#     "sent_at": "2024-01-22T06:16:20.164633+00:00"
# }



# def rGet(key):
#     return json.loads(r.get(key))

# def rSet(key,value):
#     return r.set(key,json.dumps(value))

# def extract_info(payload):
#     # Extract base price in Wei
#     base_price_wei = int(payload['payload']['base_price'])

#     # Convert Wei to Ether, considering decimals
#     base_price_ether = base_price_wei / 10**payload['payload']['payment_token']['decimals']

#     # Get USD price per Ether
#     usd_price = float(payload['payload']['payment_token']['usd_price'])

#     # Calculate base price in USD
#     base_price_usd = base_price_ether * usd_price

#     # Get maker (seller) address
#     maker_address = payload['payload']['maker']['address']

#     return {
#         'base_price_ether': base_price_ether,
#         'base_price_usd': base_price_usd,
#         'maker_address': maker_address,
#     }

    
#print(extract_info(testpayload))
# keys = redis.keys('*')
# vals = redis.mget(keys)
# for key in keys:
#     type = redis.type(key)
#     if type == "string":
#         val = redis.get(key)
#     if type == "hash":
#         vals = redis.hgetall(key)
#     if type == "zset":
#         vals = redis.zrange(key, 0, -1)
#     if type == "list":
#         vals = redis.lrange(key, 0, -1)
#     if type == "set":
#         vals = redis.smembers(key)

# kv = list(zip(keys, vals))

# print(kv)
# refreshed_token = twitter.refresh_token(
#     client_id=client_id,
#     client_secret=client_secret,
#     token_url=token_url,
#     refresh_token=data["refresh_token"],
# )


# st_refreshed_token = '"{}"'.format(refreshed_token)
# j_refreshed_token = json.loads(st_refreshed_token)


# main.r.set("token", j_refreshed_token)
# doggie_fact = main.parse_dog_fact()
# payload = {"text": "{}".format(doggie_fact)}


# main.post_tweet(payload, refreshed_token)

# twitter = main.make_token()
# client_id = os.environ.get("CLIENT_ID")
# client_secret = os.environ.get("CLIENT_SECRET")
# token_url = "https://api.twitter.com/2/oauth2/token"

# # client_creds = f"{client_id}:{client_secret}"
# # client_creds_b64 = base64.urlsafe_b64encode(client_creds.encode()).decode()


# t = main.r.get("token")
# #print(str(t))
# #bb_t = t.decode("utf8").replace("'", '"')
# data = json.loads(t)
# print(data)

# print("1111")

# # Endpoint for obtaining a new access token using a refresh token
# token_url = "https://api.twitter.com/2/oauth2/token"

# # Parameters for the refresh token request
# payload = {
#     'grant_type': 'refresh_token',
#     'refresh_token': data["refresh_token"],
#     'client_id': client_id,
#     'client_secret': client_secret
# }

# # Make the request to refresh the access token
# response = requests.post(token_url, data=payload)
# new_tokens = response.json()
# print(new_tokens)
# # Access the new access token and refresh token from the response
# new_access_token = new_tokens['access_token']
# new_refresh_token = new_tokens['refresh_token']

# # refreshed_token = twitter.refresh_token(
# #     client_id=client_id,
# #     client_secret=client_secret,
# #     token_url=token_url,
# #     refresh_token=data["refresh_token"]
# #     headers=,
# # )

# print("2222")

# st_refreshed_token = '"{}"'.format(refreshed_token)
# j_refreshed_token = json.loads(st_refreshed_token)


# main.r.set("token", j_refreshed_token)
# doggie_fact = main.parse_dog_fact()
# payload = {"text": "{}".format(doggie_fact)}


# main.post_tweet(payload, refreshed_token)
