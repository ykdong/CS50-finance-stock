import os

import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user id from session
    user_id = session["user_id"]

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Access from data
        Password = request.form.get("new_password")
        Password_again = request.form.get("new_confirmation")

        # Ensure both password was submitted
        if not Password or not Password_again:
            return apology("must provide password", 403)

        # Ensure both passwords matchs
        if Password != Password_again:
            return apology("passwords don't match", 400)

        # Hash the password
        Hash = generate_password_hash(Password, method='pbkdf2:sha256', salt_length=8)

        # Insert register information into database(finance.db)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", Hash, user_id)

        # Redirect user to home page
        flash("Password Changed!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Access bought list from database
        Bought_list = db.execute(
            "SELECT symbol, company_name, SUM(shares) as shares, share_price AS price, SUM(shares * share_price) as total FROM purchase WHERE user_id = ? GROUP BY symbol", user_id)
        Cash_select = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        Cash = Cash_select[0]["cash"]

        total_stock_list = db.execute(
            "SELECT SUM(shares * share_price) AS total FROM purchase WHERE user_id = ?", user_id)
        total_stock = total_stock_list[0]["total"]

        if total_stock == None:
            total_stock = 0
        total = total_stock + Cash
        return render_template("index.html", boughts=Bought_list, cash=usd(Cash), Total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Access from data
        Symbol = request.form.get("symbol")
        Shares = request.form.get("shares", type=int)

        # Ensure symbol was submitted
        if not Symbol:
            return apology("missing symbol", 400)

        # Ensure shares was submitted
        elif not Shares:
            return apology("missing shares", 400)

        # Ensure valid symbol
        if lookup(Symbol) == None:
            return apology("invalid symbol", 400)

        # Ensure valid shares
        if Shares < 0:
            return apology("shares must be positive", 400)
        elif not isinstance(Shares, int):
            return apology("shares must be integer", 400)

        # Ensure user has enough cash to afford the stock
        Symbol_check = lookup(Symbol)
        Buy = Symbol_check["price"] * Shares
        cash_list = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        Cash = cash_list[0]["cash"]
        if Buy > Cash:
            return apology("can't afford", 400)

        # No error detected, complete the purchase and update related data
        user_id = session["user_id"]
        price = Symbol_check["price"]
        symbol = Symbol_check["symbol"]
        company_name = Symbol_check["name"]
        time = datetime.datetime.now()
        action = "BUY"
        new_cash = Cash - Buy
        db.execute("INSERT INTO purchase(user_id, share_price, symbol, shares, transacted, total, company_name, action) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                user_id, price, symbol, Shares, time, Buy, company_name, action)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Update compated, render data to homepage
        flash("Bought!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Remember user id
    user_id = session["user_id"]

    # Access data from database
    history_list = db.execute(
        "SELECT symbol, shares, share_price, transacted FROM purchase WHERE user_id = ? ORDER BY transacted", user_id)

    # Render history page
    return render_template("history.html", historys=history_list)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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
    return redirect("/login")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure valid symbol
        symbol = request.form.get("symbol")
        if lookup(symbol) == None:
            return apology("invalid symbol", 400)

        # Access quote information
        quote = lookup(symbol)
        message = "A share of " + quote["name"] + " (" + quote["symbol"] + ") costs " + usd(quote["price"]) + "."
        return render_template("quoted.html", message=message)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Access from data
        Username = request.form.get("username")
        Password = request.form.get("password")
        Password_again = request.form.get("confirmation")

        # Ensure username and password was submitted
        if not Username or not Password or not Password_again:
            return apology("must provide username and/or password", 400)

        # Ensure both passwords matchs
        if Password != Password_again:
            return apology("passwords don't match", 400)

        # Ensure username is valid
        is_username_taken = db.execute("SELECT * FROM users WHERE username = ?", Username)
        if len(is_username_taken) == 1:
            return apology("Username is not available", 400)

        # Hash the password
        Hash = generate_password_hash(Password, method='pbkdf2:sha256', salt_length=8)

        # Insert register information into database(finance.db)
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", Username, Hash)

        # Remember the user logged in, store the information into session
        rows = db.execute("SELECT * FROM users WHERE username = ?", Username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Registered!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Remember user id
    user_id = session["user_id"]

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Access from data
        Symbol = request.form.get("symbol")
        Shares = request.form.get("shares", type=int)

        # Ensure symbol was submitted
        if not Symbol:
            return apology("missing symbol", 400)

        # Ensure shares was submitted
        elif not Shares:
            return apology("missing shares", 400)

        # Ensure valid shares input
        if Shares < 0:
            return apology("shares must be positive", 400)
        elif not isinstance(Shares, int):
            return apology("shares must be integer", 400)
        shares_in_db = db.execute(
            "SELECT SUM(shares) AS shares FROM purchase WHERE user_id = ? AND symbol = ? AND action = ? GROUP BY symbol", user_id, Symbol, "BUY")
        if Shares > shares_in_db[0]["shares"] or shares_in_db[0]["shares"] == None:
            return apology("too many shares", 400)

        # No error detected, complete the sell process and update related data
        Symbol_check = lookup(Symbol)
        price = Symbol_check["price"]
        symbol = Symbol_check["symbol"]
        company_name = Symbol_check["name"]
        action = "SELL"
        Sell = price * Shares
        time = datetime.datetime.now()
        cash_list = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        Cash = cash_list[0]["cash"]
        new_cash = Cash + Sell
        db.execute("INSERT INTO purchase(user_id, share_price, symbol, shares, transacted, total, company_name, action) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                   user_id, price, symbol, (Shares*-1), time, Sell, company_name, action)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Update compated, render data to homepage
        flash("Sold!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        Symbols = db.execute("SELECT DISTINCT symbol FROM purchase WHERE user_id = ?", user_id)
        return render_template("sell.html", Symbols=Symbols)
