import json
from io import BytesIO
from flask import Flask, request, Blueprint, send_file, render_template

from application.util.database import Database
from application.util.general import response
from application.util.auth import verify_access_token
from application.util.document import HTML2PDF

web = Blueprint("web", __name__)

@web.before_request
def before_request():
  auth_header = request.headers.get("Authorization")
  if not auth_header or "Bearer" not in auth_header:
    return response("Access token does not exist"), 400
  
  access_token = auth_header[7:]
  access_token = verify_access_token(access_token)

  if not access_token:
    return response("Access token is invalid"), 400
  
  request.user_data = access_token


def admin_middleware(func):
  def check_admin(*args, **kwargs):
    if request.user_data["user_type"] != "administrator":
      return response("Restricted to administrators"), 400

    return func(*args, **kwargs)

  check_admin.__name__ = func.__name__
  return check_admin


@web.route("/", methods = ["GET"])
def index():
  return response("OK"), 200


@web.route("/products/<identifier>", methods = ["GET"])
def products(identifier):
  if not identifier:
    return response("No product id"), 400

  db_session = Database()

  if identifier == "all":
    products = db_session.get_all_products()

    if not products:
      return response("No products found"), 200

    return response(products), 200

  else:
    product = db_session.get_product(identifier)

    if not product:
      return response("No products found"), 200

    return response(product), 200


@web.route("/order/<identifier>", methods = ["POST"])
def order(identifier):
  if not identifier:
    return response("No product id"), 400

  db_session = Database()
  product = db_session.get_product(identifier)

  if not product:
    return response("No products found"), 200

  db_session.create_order(product["id"], request.user_data["user_id"])
  return response("Order placed"), 200


@web.route("/orders", methods = ["GET"])
@admin_middleware
def orders():
  db_session = Database()
  orders = db_session.get_all_orders()
  return response(orders), 200


@web.route("/orders/html", methods = ["POST"])
@admin_middleware
def orders_html():
  color = request.form.get("color")

  if not color:
    return response("No color"), 400

  db_session = Database()
  orders = db_session.get_all_orders()
  
  if not orders:
    return response("No orders placed"), 200

  orders_template = render_template("orders.html", color=color)
  
  html2pdf = HTML2PDF()
  pdf = html2pdf.convert(orders_template, orders)
  
  pdf.seek(0)
  return send_file(pdf, as_attachment=True, download_name="orders.pdf", mimetype="application/pdf")