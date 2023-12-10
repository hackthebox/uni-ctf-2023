import cryptography, jwt
from flask import current_app

ISSUER = "phantomfeed-auth-server"

def verify_access_token(access_token):
  try:
    decoded_token = jwt.decode(access_token, current_app.config["PUBLIC_KEY"], issuer=ISSUER, algorithms=["RS256"])
  except (jwt.exceptions.InvalidTokenError,
          jwt.exceptions.InvalidSignatureError,
          jwt.exceptions.InvalidIssuerError,
          jwt.exceptions.ExpiredSignatureError):
    return False

  return decoded_token
