import os
import redis

r = redis.from_url(os.environ["REDIS_URL_DOGS"])
current_token=r.get("token")
current_save_token=r.get("save_token")

print(f"current_token: {current_save_token}")

print(f"current_save_token: {current_save_token}")