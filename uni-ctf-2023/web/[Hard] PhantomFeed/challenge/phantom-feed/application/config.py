import os
from dotenv import load_dotenv
from application.util.general import generate

from datetime import datetime, timedelta
import jwt

load_dotenv()

with open(os.path.abspath("private.pem"), "rb") as file:
    private_key = file.read()

with open(os.path.abspath("public.pem"), "rb") as file:
    public_key = file.read()

class Config(object):
	SECRET_KEY = generate(50)
	ISSUER = "phantomfeed-auth-server"
	CODE_LIFE_SPAN = 600
	JWT_LIFE_SPAN = 1800
	PRIVATE_KEY = private_key
	PUBLIC_KEY = public_key


class ProductionConfig(Config):
	pass


class DevelopmentConfig(Config):
	DEBUG = False


class TestingConfig(Config):
	TESTING = False