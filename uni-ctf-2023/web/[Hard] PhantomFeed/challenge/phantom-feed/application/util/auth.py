import base64, cryptography, json, jwt, time
from flask import current_app
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

from application.util.database import Database

KEY = Fernet.generate_key()

db_session = Database()

def create_jwt(user_id, username):
  payload = {
    "iss": current_app.config["ISSUER"],
    "exp": datetime.utcnow() + timedelta(seconds=current_app.config["JWT_LIFE_SPAN"]),
    "user_id": user_id,
    "username": username,
    "user_type": "administrator" if username == "administrator" else "user"
  }

  token = jwt.encode(payload, current_app.config["PRIVATE_KEY"], algorithm="RS256")

  return token


def verify_jwt(token):
  try:
    decoded_token = jwt.decode(token, current_app.config["PUBLIC_KEY"], algorithms=["RS256"])
    return decoded_token
  except jwt.InvalidTokenError:
    return False


def generate_authorization_code(username, client_id, redirect_url):
  authorization_code = Fernet(KEY).encrypt(json.dumps({
    "client_id": client_id,
    "redirect_url": redirect_url,
  }).encode())

  authorization_code = base64.b64encode(authorization_code, b"-_").decode().replace("=", "")
  expiration_date = datetime.utcnow() + timedelta(seconds=current_app.config["CODE_LIFE_SPAN"])
  db_session.create_auth_code(authorization_code, client_id, redirect_url, expiration_date)
 
  return authorization_code


def verify_authorization_code(authorization_code, client_id, redirect_url):
  record = db_session.get_auth_code(authorization_code)
 
  if not record:
    return False
  
  client_id_in_record = record.client_id
  redirect_url_in_record = record.redirect_url
  exp = record.exp

  if client_id != client_id_in_record or redirect_url != redirect_url_in_record:
    return False

  if exp < datetime.utcnow():
    return False

  db_session.del_auth_code(authorization_code)

  return True