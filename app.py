import os
from datetime import datetime
from sql import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import error, login_required

# Configure application
app = Flask(__name__)

# Configure SQL Library to use SQLite database
db = SQL("sqlite:///lab.db")

# Ensure templates are auto-reloaded
# EACH reROuting is a REload
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    # this is the point in which i tell the browser to not to WORRY about cache
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    # information has zero refresh time , it will be stale upon GET REquest no refresh or live FEEDing
    response.headers["Expires"] = 0
    # any old browser will auto matically calling via http1.1/1 versions old pragma code is also notified
    response.headers["Pragma"] = "no-cache"
    return response


# Configure  to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
# changing this to TRUE will give user infinitie login time even after RESTARTing thier device 
app.config["SESSION_PERMANENT"] = False
# it Ensures that our we app should use only the file sysytem DATABASE not the users file systems , 
# POINT: May protect us from any HACKER trying to pull whole database into local machine
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/")
@login_required
def index():
    row = db.execute("""SELECT username FROM users
    WHERE id = :user_id;
    """,user_id=session['user_id'])
    username = row[0]["username"]
    return render_template("home.html",username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return error("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return error("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return error("invalid username and  password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/andgate")
@login_required
def andgate():
    return render_template("and_gate.html")

@app.route("/orgate")
@login_required
def orgate():
    return render_template("or_gate.html")

@app.route("/xorgate")
@login_required
def xorgate():
    return render_template("xor_gate.html")

@app.route("/xnorgate")
@login_required
def xnorgate():
    return render_template("xnor_gate.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        uname = request.form.get('username')
        password = generate_password_hash(request.form.get('password'))
        status = True
        # check password confirmation
        if not request.form.get('password') == request.form.get('confirmation'):
            status = False
            text = "Passwords do not match"
        # check unique username
        exists_username= db.execute("SELECT username FROM users where username = :username", username = uname)
        if exists_username:
            status = False
            text = "Sorry Username already taken by another user"
        if status:
            # register
            register = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
            username = uname, hash = password)
            text = "Registration Successfully Done!"
            # Remember which user has logged in
            session["user_id"] = register

            # Redirect user to home page
            return redirect("/")
        return error(text)
    else:
        return render_template("register.html")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change her password"""

    if request.method == "POST":

        # Ensure current password is not empty
        if not request.form.get("current_password"):
            return error("must provide current password", 400)

        # Query database for user_id
        rows = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return error("invalid password", 400)

        # Ensure new password is not empty
        if not request.form.get("new_password"):
            return error("must provide new password", 400)

        # Ensure new password confirmation is not empty
        elif not request.form.get("new_password_confirmation"):
            return error("must provide new password confirmation", 400)

        # Ensure new password and confirmation match
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return error("new password and confirmation must match", 400)

        # Update database
        hash = generate_password_hash(request.form.get("new_password"))
        rows = db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)

        # Show flash
        flash("Changed!")

    return render_template("change_password.html")


def errorhandler(e):
    # print("e:::",e)
    # print(" e.name:::",e.name)
    # print(" e.code:::",e.code)
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return error(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
