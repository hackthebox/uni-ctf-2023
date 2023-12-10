from application.app import app
from application.util.database import Database

db_session = Database()
db_session.migrate()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000, threaded=True, debug=False)
