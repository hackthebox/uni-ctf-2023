import os
from flask import jsonify
from faker import Faker

fake = Faker()

generate = lambda x: os.urandom(x).hex()

def generate_user():
    return fake.user_name()


def generate_email():
    return fake.email()