# app/routes.py
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from . import models

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    username = session.get("username")
    balance = models.get_balance(username) if username else None
    return render_template("index.html", username=username, balance=balance)


@bp.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for("main.index"))

    created = models.create_user(username, password, starting_balance=1000)
    if not created:
        flash("User already exists.")
    else:
        flash(f"User {username} registered with starting balance 1000.")

    return redirect(url_for("main.index"))


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not models.verify_password(username, password):
        flash("Invalid username or password.")
        return redirect(url_for("main.index"))

    session["username"] = username
    flash(f"Logged in as {username}.")
    return redirect(url_for("main.index"))


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("main.index"))


@bp.route("/transfer", methods=["POST"])
def transfer():
    username = session.get("username")
    if not username:
        flash("You must be logged in.")
        return redirect(url_for("main.index"))

    to_user = request.form.get("to_user", "").strip()
    amount_str = request.form.get("amount", "").strip()

    try:
        amount = int(amount_str)
    except ValueError:
        flash("Invalid amount.")
        return redirect(url_for("main.index"))

    ok, msg = models.transfer(username, to_user, amount)
    flash(msg)
    return redirect(url_for("main.index"))


@bp.route("/change_password", methods=["POST"])
def change_password():
    username = session.get("username")
    if not username:
        flash("You must be logged in.")
        return redirect(url_for("main.index"))

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not models.verify_password(username, old_password):
        flash("Old password incorrect.")
        return redirect(url_for("main.index"))

    models.change_user_password(username, new_password)
    flash("Password changed.")
    return redirect(url_for("main.index"))


@bp.route("/_health")
def health():
    return "OK", 200