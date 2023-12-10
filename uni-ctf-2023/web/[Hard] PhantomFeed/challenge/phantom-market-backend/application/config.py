import os
from dotenv import load_dotenv
from application.util.general import generate

load_dotenv()

with open(os.path.abspath("public.pem"), "rb") as file:
    public_key = file.read()

class Config(object):
	SECRET_KEY = generate(50)
	PUBLIC_KEY = public_key


class ProductionConfig(Config):
	pass


class DevelopmentConfig(Config):
	DEBUG = False


class TestingConfig(Config):
	TESTING = False