import main
import redis
import json
import os
import base64
# twitter = main.make_token()
# client_id = os.environ.get("CLIENT_ID")
# client_secret = os.environ.get("API_SECRET")
# token_url = "https://api.twitter.com/2/oauth2/token"
# t = main.r.get("token")
# bb_t = t.decode("utf8").replace("'", '"')
# data = json.loads(bb_t)

# refreshed_token = twitter.refresh_token(
#     client_id=client_id,
#     client_secret=client_secret,
#     token_url=token_url,
#     refresh_token=data["refresh_token"],
# )

# st_refreshed_token = '"{}"'.format(refreshed_token)
# j_refreshed_token = json.loads(st_refreshed_token)
# main.r.set("token", j_refreshed_token)
# print(json.dumps(j_refreshed_token))

string='Aladdin:open sesame'
encoded_credentials = base64.urlsafe_b64encode(string.encode()).decode()
print(encoded_credentials)