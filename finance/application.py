import os
import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Extracting symbols and their shares
    symbols_info = db.execute("SELECT symbol, shares FROM info WHERE user_id = ?", session["user_id"])

    # Temp variable to calculate total balance
    total_balance = 0

    # Going through each symbol and updating them
    for symbol_info in symbols_info:
        symbol = symbol_info["symbol"]
        shares = symbol_info["shares"]
        cost = lookup(symbol)
        total = shares * cost["price"]
        total_balance += total

        db.execute("UPDATE info SET cost = ?, total = ? WHERE user_id = ? AND symbol = ?", cost["price"], total, session["user_id"], symbol)

    # Getting cash value from users table
    row = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    # Setting a variable value to cash value of user
    balance = row[0]["cash"]

    # Updating total balance
    total_balance += balance

    # Getting all the data
    all_info = db.execute("SELECT * FROM info WHERE user_id = ?", session["user_id"])

    return render_template("index.html", all_info = all_info, balance = usd(balance), total_balance = usd(total_balance), usd = usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Fetching all the values
        symbol = request.form.get("symbol")
        cost = lookup(symbol)
        name = lookup(symbol)
        time = datetime.datetime.now()

        # To avoid error from client side
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares cant be decimal", 400)

        # Checking if symbol entered is correct
        if not symbol:
            return apology("You have not entered any valid symbol", 400)

        # Checking if user entered any number in shares
        elif not shares:
            return apology("Enter the number of shares you want to buy", 400)

        # Giving an apology if user enters negative number of shares
        elif int(shares) < 0:
            return apology("Shares must be positive")

        if lookup(symbol) is None:
            return apology("Invalid symbol", 400)

        # Extracting cash column from table
        row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Getting value from table and assigning it to a variable
        balance = row[0]["cash"]

        # Doing some calculations
        cash = float(balance) - (cost["price"] * float(shares))

        # Checking if user has sufficient balance
        if float(cash) < (cost["price"] * float(shares)):
            return apology("Not enough cash", 400)

        else:
            db.execute("INSERT INTO purchases (symbol, shares, cost, status, transacted, user_id) VALUES (?, ?, ?, ?, ?, ?)", symbol, shares, cost["price"], "BOUGHT", time.strftime("%d-%m-%Y %I:%M:%S"), session["user_id"])
            db.execute("UPDATE users SET cash = ? WHERE id = ? ", cash, session["user_id"])

        # Getting user shares
        user_shares = db.execute("SELECT shares FROM info WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        # If user doesnt share of that particular symbol
        if not user_shares:
            db.execute("INSERT INTO info (symbol, name, shares, cost, total, user_id) VALUES (?, ?, ?, ?, ?, ?)", symbol, name["name"], shares, cost["price"], cost["price"] * float(shares), session["user_id"])

        # and if they have then add it to particular symbol
        else:
            total_shares = user_shares[0]["shares"] + int(shares)
            db.execute("UPDATE info SET shares = ? WHERE user_id = ? AND symbol = ?", total_shares, session["user_id"], symbol)

        # Return to homepage
        return redirect("/")


    else:

        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    #Fetching data from table
    purchases = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])

    return render_template("history.html", purchases = purchases, usd = usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # Getting all the required data
        symbol = request.form.get("symbol")
        name = lookup(symbol)
        cost = lookup(symbol)
        abrev = lookup(symbol)

        # If the symbol is not valid
        if not symbol:
            return apology("You have not entered anything", 400)

        # If symbol doesnt exist and returns None
        if abrev is None:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", name=name, cost=cost, abrev=abrev, usd=usd)

    else:

        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Getting all the required data
        user = request.form.get("username")
        password = request.form.get("password")
        confirm_pass = request.form.get("confirmation")
        hash_password = generate_password_hash(password)

        # Showing error if user does not provide username
        if not user:
            return apology("must provide username", 400)

        # Showing error if user does not provide password
        elif not password:
            return apology("must provide password", 400)

        # Showing error if user does not provide confirmation password
        elif not confirm_pass:
            return apology("must provide password", 400)

        elif password != confirm_pass:
            return apology("password doesnt match", 400)

        # Getting data from table
        try:
            users = db.execute("SELECT * FROM users WHERE username = ?", user)

            user_data = users[0]["username"]

            if user == user_data:
                return apology("username already exists", 400)

        except Exception as e:
            print(e)

        # Inserting user's username and hash password
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", user, hash_password)

        # Redirecting user to login page
        return redirect("/login")

    else:

        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Fetching all values that are required
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        cost = lookup(symbol)
        name = lookup(symbol)
        time = datetime.datetime.now()

        # Giving an error if user havent selected any symbol
        if not symbol:
            return apology("Select a company", 400)

        # Giving an error if user havent entered any no. of shares
        if not shares:
            return apology("Select no. of shares", 400)

        # Giving an error if user have entered negative number of shares
        if int(shares) < 0:
            return apology("You are required to enter positive number")

        # If no symbol is selected then or if it doesnt exist
        if lookup(symbol) is None:
            return apology("Invalid symbol", 400)

        # Extracting data from table
        row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Using a variable to store value of cash user have
        balance = row[0]["cash"]

        # User's balance calculation
        cash = float(balance) + (cost["price"] * float(shares))

        # Getting shares of particular symbol
        user_shares = db.execute("SELECT shares FROM info WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        # Checking if user has enough shares
        if not user_shares or user_shares[0]["shares"] < int(shares):
            return apology("Not enough shares")

        else:
            # Inserting data into table
            db.execute("INSERT INTO purchases (symbol, shares, cost, status, transacted, user_id) VALUES (?, ?, ?, ?, ?, ?)", symbol, shares, cost["price"], "SOLD", time.strftime("%d-%m-%Y %I:%M:%S"), session["user_id"])

            # Updating cash column of user
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        # Calculating total shares
        total_shares = user_shares[0]["shares"] - int(shares)

        #If total shares are 0 then deleting the shares
        if total_shares == 0:
            db.execute("DELETE FROM info WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        # If not then updating the shares
        else:
            db.execute("UPDATE info SET shares = ? WHERE user_id = ? AND symbol = ?", total_shares, session["user_id"], symbol)

        # Going back to homepage
        return redirect("/")

    else:

        # To get every symbol from table (There are multiples data of similar symbol thats why)
        companies = db.execute("SELECT DISTINCT(symbol) FROM purchases WHERE user_id = ?", session["user_id"])

        return render_template("sell.html", companies= companies)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
