import redis
import os

r = redis.from_url(os.environ["REDIS_URL_DOGS"])
