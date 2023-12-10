from flask import Flask, send_file

app = Flask(__name__)


@app.route("/WJveX71agmOQ6Gw_1698762642.jpg", methods=["GET"])
def start():
    return send_file("/web/WJveX71agmOQ6Gw_1698762642.jpg")


@app.route("/d/BKtQR", methods=["GET"])
def decoy():
    return send_file("/web/BKtQR")


if __name__ == "__main__":
    app.run(host="0.0.0.0")