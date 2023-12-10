from flask import Flask, send_file

app = Flask(__name__)


@app.route("/", methods=["POST"])
def root():
    return "OK"

@app.route("/callback", methods=["POST"])
def callback():
    return "OK"


@app.route("/reanimate", methods=["POST"])
def reanimate():
    return "OK"


@app.route("/reanimate.sh_jEzOWMtZTUxOS00", methods=["GET"])
def start():
    return send_file("/web/reanimate.sh_jEzOWMtZTUxOS00")


@app.route("/dead_reanimated_mNmZTMtNjU3YS00", methods=["GET"])
def decoy():
    return send_file("/web/dead_reanimated_mNmZTMtNjU3YS00")


if __name__ == "__main__":
    app.run(host="0.0.0.0")
