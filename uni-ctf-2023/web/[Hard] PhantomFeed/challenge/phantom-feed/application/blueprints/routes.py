import json, time
from flask import Flask, redirect, render_template, request, Blueprint, current_app, make_response, url_for

from application.util.database import Database
from application.util.email import EmailClient
from application.util.bot import bot_runner
from application.util.auth import create_jwt, verify_jwt, generate_authorization_code, verify_authorization_code

web = Blueprint("web", __name__)

def auth_middleware(func):
  def check_user(*args, **kwargs):
    jwt_cookie = request.cookies.get("token")
    if not jwt_cookie:
      return redirect("/phantomfeed/login")

    token = verify_jwt(jwt_cookie)
    
    if not token:
      return redirect("/phantomfeed/login")

    request.user_data = token

    return func(*args, **kwargs)

  check_user.__name__ = func.__name__
  return check_user


@web.route("/", methods=["GET"])
def index():
  return redirect("/phantomfeed/feed")


@web.route("/login", methods=["GET", "POST"])
def login():
  if request.method == "GET":
    return render_template("login.html", title="log-in")

  if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")

  if not username or not password:
    return render_template("error.html", title="error", error="missing parameters"), 400

  db_session = Database()
  user_valid, user_id = db_session.check_user(username, password)

  if not user_valid:
    return render_template("error.html", title="error", error="invalid username/password or not verified"), 401

  token = create_jwt(user_id, username)

  response = make_response(redirect("/phantomfeed/feed"))
  response.set_cookie("token", token, samesite="Strict", httponly=True)
  return response


@web.route("/register", methods=["GET", "POST"])
def register():
  if request.method == "GET":
    return render_template("register.html", title="register")

  if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

  if not username or not password or not email:
    return render_template("error.html", title="error", error="missing parameters"), 400

  db_session = Database()
  user_valid, user_id = db_session.create_user(username, password, email)
  
  if not user_valid:
    return render_template("error.html", title="error", error="user exists"), 401

  email_client = EmailClient(email)
  verification_code = db_session.add_verification(user_id)
  email_client.send_email(f"http://phantomfeed.htb/phantomfeed/confirm?verification_code={verification_code}")

  return render_template("error.html", title="error", error="verification code sent"), 200


@web.route("/confirm", methods=["GET"])
def confirm():
  verification_code = request.args.get("verification_code")
  if not verification_code:
    return render_template("error.html", title="error", error="missing parameters"), 400

  db_session = Database()
  code_verified = db_session.check_verification(verification_code)

  if not code_verified:
    return render_template("error.html", title="error", error="invalid verification code"), 400

  return redirect("/phantomfeed/login")


@web.route("/logout", methods=["GET"])
def logout():
    resp = make_response(redirect("/phantomfeed/login"))
    resp.set_cookie("token", "", expires=0)
    resp.set_cookie("access_token", "", expires=0)
    return resp, 302


@web.route("/feed", methods=["GET", "POST"])
@auth_middleware
def feed():
  if request.method == "GET":
    db_session = Database()
    posts = db_session.get_all_posts()

    return render_template("feed.html", title="feed", nav_enabled=True, user_data=request.user_data, posts=posts)

  if request.method == "POST":
    content = request.form.get("content")
    market_link = request.form.get("market_link")

  if not content or not market_link:
    return render_template("error.html", title="error", error="missing parameters"), 400

  if market_link == "":
    return render_template("error.html", title="error", error="invalid market link"), 401
  
  db_session = Database()
  db_session.create_post(request.user_data["user_id"], request.user_data["username"], content, market_link)

  bot_runner(market_link)

  return redirect("/phantomfeed/feed")


@web.route("/about", methods=["GET"])
@auth_middleware
def about():
  return render_template("about.html", title="about", nav_enabled=True, user_data=request.user_data)


@web.route("/marketplace", methods=["GET"])
@auth_middleware
def marketplace():
  return redirect("/")


@web.route("/oauth2/auth", methods=["GET"])
@auth_middleware
def auth():
  client_id = request.args.get("client_id")
  redirect_url = request.args.get("redirect_url")

  if not client_id or not redirect_url:
    return render_template("error.html", title="error", error="missing parameters"), 400

  return render_template("oauth2.html",
    title="oauth2 authorization",
    client_id = client_id,
    redirect_url = redirect_url
  )


@web.route("/oauth2/code", methods=["GET"])
@auth_middleware
def oauth2():
  client_id = request.args.get("client_id")
  redirect_url = request.args.get("redirect_url")

  if not client_id or not redirect_url:
    return render_template("error.html", title="error", error="missing parameters"), 400
    
  authorization_code = generate_authorization_code(request.user_data["username"], client_id, redirect_url)
  url = f"{redirect_url}?authorization_code={authorization_code}"

  return redirect(url, code=303)


@web.route("/oauth2/token", methods=["GET"])
@auth_middleware
def token():
  authorization_code = request.args.get("authorization_code")
  client_id = request.args.get("client_id")
  redirect_url = request.args.get("redirect_url")

  if not authorization_code or not client_id or not redirect_url:
    return render_template("error.html", title="error", error="missing parameters"), 400

  if not verify_authorization_code(authorization_code, client_id, redirect_url):
    return render_template("error.html", title="error", error="access denied"), 401

  access_token = create_jwt(request.user_data["user_id"], request.user_data["username"])
  
  return json.dumps({ 
    "access_token": access_token,
    "token_type": "JWT",
    "expires_in": current_app.config["JWT_LIFE_SPAN"],
    "redirect_url": redirect_url
  })