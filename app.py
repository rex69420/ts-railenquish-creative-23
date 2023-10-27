import subprocess
from base64 import b64encode
from json import loads

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo

from flask_session import Session

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = "teksyndi46"
app.config[
    "MONGO_URI"
] = "mongodb+srv://rex:5oS0U6qcACS873YZ@cluster0.p7aklfk.mongodb.net/flask_testing"
app.config["SESSION_TYPE"] = "filesystem"
app.config["TEMPLATES_AUTO_RELOAD"] = True
Session(app)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)


@app.route("/")
def index():
    if "username" in session:
        authenticated = True
    else:
        authenticated = False
    return render_template("index.html", auth=authenticated)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = mongo.db.users.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            # Successful login
            session["username"] = username  # Store username in the session
            flash("Login successful", "success")
            return redirect(url_for("index"))
        else:
            flash("Login failed. Check your credentials.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("reg_username")
        password = request.form.get("reg_password")
        existing_user = mongo.db.users.find_one({"username": username})

        if existing_user:
            flash(
                "Username already exists. Please choose a different username.", "danger"
            )
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            mongo.db.users.insert_one(
                {"username": username, "password": hashed_password}
            )
            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/trains")
def display_train_data():
    if "username" in session:
        return render_template("train_form.html")
    else:
        return redirect(url_for("index"))


@app.route("/pnr")
def display_pnr_data():
    if "username" in session:
        return render_template("pnr.html")
    else:
        return redirect(url_for("index"))


def encrypt_pnr(pnr):
    """
    Encrypts the PNR number using AES-128-CBC.
    """
    data = bytes(pnr, "utf-8")
    backend = default_backend()
    padder = padding.PKCS7(128).padder()

    data = padder.update(data) + padder.finalize()
    key = b"8080808080808080"
    iv = b"8080808080808080"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    enc_pnr = b64encode(ct)
    return enc_pnr.decode("utf-8")


@app.route("/get_pnr_info")
def get_pnr_info():
    """
    Returns PNR status in JSON format.
    """
    pnr = request.args.get("pnr")
    if pnr is None:
        return "PNR not provided.", 400
    if len(pnr) != 10:
        return "PNR Length Incorrect.", 400
    encrypted_pnr = encrypt_pnr(pnr)
    json_data = {
        "pnrNumber": encrypted_pnr,
    }
    response = requests.post(
        "https://railways.easemytrip.com/Train/PnrchkStatus",
        json=json_data,
        verify=True,
    )
    response.raise_for_status()
    json_data = loads(response.content)
    # if json_data["chartStatus"] == "Chart Not Prepared":
    #     return "Chart not prepared.", 400
    return json_data


@app.route("/get_train_info", methods=["GET"])
def get_train_info():
    from_station = request.args.get("from_station")
    to_station = request.args.get("to_station")
    date = request.args.get("date")

    if from_station is None or to_station is None or date is None:
        return "Invalid parameters.", 400
    # credit to AniCrad on github for the api
    url = f"https://indian-railway-api.cyclic.app/trains/gettrainon?from={from_station}&to={to_station}&date={date}"
    data = requests.get(url).json()
    if data["success"]:
        return data
    else:
        return "No trains found. Try again.", 400


if __name__ == "__main__":
    app.run(debug=True)
