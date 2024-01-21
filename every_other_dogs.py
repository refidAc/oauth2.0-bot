import main 
import json
import os
import base64
import requests
import main 
import json
import os


twitter = main.make_token()
client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
token_url = "https://api.twitter.com/2/oauth2/token"


t = main.r.get("token")
bb_t = t.decode("utf8").replace("'", '"')
data = json.loads(bb_t)


refreshed_token = twitter.refresh_token(
    client_id=client_id,
    client_secret=client_secret,
    token_url=token_url,
    refresh_token=data["refresh_token"],
)


st_refreshed_token = '"{}"'.format(refreshed_token)
j_refreshed_token = json.loads(st_refreshed_token)


main.r.set("token", j_refreshed_token)
doggie_fact = main.parse_dog_fact()
payload = {"text": "{}".format(doggie_fact)}


main.post_tweet(payload, refreshed_token)

# twitter = main.make_token()
# client_id = os.environ.get("CLIENT_ID")
# client_secret = os.environ.get("CLIENT_SECRET")
# token_url = "https://api.twitter.com/2/oauth2/token"

# # client_creds = f"{client_id}:{client_secret}"
# # client_creds_b64 = base64.urlsafe_b64encode(client_creds.encode()).decode()


# t = main.r.get("raw_token")
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
