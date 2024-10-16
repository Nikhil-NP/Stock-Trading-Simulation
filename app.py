import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application

app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute(
        "SELECT username,cash FROM users WHERE id = ?", session["user_id"]
    )  # query to get username and cash avilable
    username = rows[0]["username"]  # assigning the values
    cash = rows[0]["cash"]
    rows2 = db.execute(
        "SELECT stock_symbol,number_of_shares FROM purchases WHERE user_id = ? ",
        session["user_id"]##########
    )  # getting stock info
    stocks = []  # list to store the info about shares
    if len(rows2) > 0:
        for (
            row
        ) in (
            rows2
        ):  # this will get all the details that are specified in this part to render in index.html
            stock_symbol = row["stock_symbol"]
            stock_info = lookup(stock_symbol)
           
            stock_info["number_of_shares"] = row["number_of_shares"]
            shares = stock_info["number_of_shares"]
            price = stock_info["price"]
            stock_info["holdings_value"] = shares * price
            stocks.append(stock_info)
        gt = round(sum(value["holdings_value"] for value in stocks) + cash, 2)
        # getting the total of holding stock  and cash
        # round(cash,2)
        return render_template(
            "index.html", username=username, stocks=stocks, cash=round(cash, 2), gt=gt
        )
    else:
        return render_template(    "index.html", username=username, stocks=stocks, cash=round(cash, 2), gt=0)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # return apology("TODO")
    if request.method == "POST":  # checking if valid int
        symbol = request.form.get("symbol")  # getting symbol from buy.html
        lookup_symb = lookup(
            symbol
        )  # note this contanins a dictnary and needs to be further accessed the symbol
        print("---------------------------------------------")
        print(lookup_symb)
        print("---------------------------------------------")
        if not lookup_symb or not symbol:
            return apology("Symbol doesnt exist")
        # here i will check the quantity
        try:  # if the string is a int equivalet
            shares = int(request.form.get("shares"))  # converting it if true
        except ValueError:
            return apology("Invalid share quantity")
        if shares <= 0:  # making sure its not negitive
            return apology("Invaild Share Quantity")

        # print("the current price:",lookup_symb["price"])

        # here the user_id is named placeholder represented with a ":"
        rows = db.execute(
            "SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"]
        )

        # print("the bank balance is ",rows[0]["cash"])
        cash = rows[0]["cash"]
        order_total = lookup_symb["price"] * shares

        if cash < order_total:  # cheking if bank has enough cash
            return apology("Not Sufficent Funds")
        cash = round(cash - order_total, 2)  # changing the balalnce after purchase
        type = "BUY"  # string declard later used in query
        db.execute(
            "UPDATE users  SET cash = ? WHERE id = ?", cash, session["user_id"]
        )  # updating the new cash value in database

        # checking if user already holds stock of this compony,if yes just update the
        rows2 = db.execute(
            "select * from purchases where user_id = ? and stock_symbol = ?",
            session["user_id"],
            lookup_symb["symbol"],
        )

        if len(rows2) > 0:  # making sure stock exsits if so
            no_of_shares = int(
                rows2[0]["number_of_shares"]
            )  # getting the total shares exsiting
            db.execute(
                "INSERT INTO transactions (user_id,stock_symbol,number_of_shares,price,type,datetime) VALUES (?,?,?,?,?,datetime('now'))",
                session["user_id"],
                lookup_symb["symbol"],
                shares,
                lookup_symb["price"],
                type,
            )
            shares = shares + no_of_shares  # updating the shares no
            db.execute(
                "UPDATE purchases SET number_of_shares = ? WHERE user_id = ? and stock_symbol= ?",
                shares,
                session["user_id"],
                lookup_symb["symbol"],
            )
            return redirect("/")  # redirected index page

        db.execute(
            "INSERT INTO transactions (user_id,stock_symbol,number_of_shares,price,type,datetime) VALUES (?,?,?,?,?,datetime('now'))",
            session["user_id"],
            lookup_symb["symbol"],
            shares,
            lookup_symb["price"],
            type,
        )
        db.execute(
            "INSERT INTO purchases (user_id, stock_symbol, number_of_shares, type,  datetime) VALUES (?, ?, ?, ?, datetime('now'))",
            session["user_id"],
            lookup_symb["symbol"],
            shares,
            type,
        )
        # creating a record of the data stored

        return redirect("/")  # redirected index page

    else:
        return render_template("buy.html")  # get request


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # return apology("TODO")
    rows = db.execute(
        "Select * from transactions where user_id = ?", session["user_id"]
    )
    return render_template("history.html", rows=rows)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # return apology("TODO")
    if request.method == "POST":  # reciving user input
        stock = request.form.get("symbol")
        quote = lookup(stock)  # lookup
        print("---------------------------------------------")
        print(quote)
        print("---------------------------------------------")
        if not quote:  # lookup  deosnt exist check
            return apology("invalid symbol")
        else:
            return render_template(
                "quoted.html", stock=quote, price=usd(quote["price"])
            )

    else:  # get method show template
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":  # as we sending info to databese lets use post
        username = request.form.get(
            "username"
        )  # reciving info from input box of register.html
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username or not password or not confirmation:  # checking if its empty
            return apology("enter valid input")
        if password != confirmation:  # checking if both passowrd match
            return apology("enter the same password")
        check_db = db.execute(
            "select username from users where username = ?", username
        )  # getting the rows from sql query if there exist same user
        if len(check_db) == 1:  # id len = 1 means there is 1 row already
            return apology("username exists")
        else:
            hashed_pass = generate_password_hash(password)  # generationg hased password
            db.execute(
                "insert into users (username,hash,cash) values (?,?,10000.00)",
                username,
                hashed_pass,
            )  # insertion
            return redirect("/login")  # redirect to the page
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        lookup_symb = lookup(
            symbol
        )  # note this contanins a dictnary and needs to be further accessed the symbol
        print(lookup_symb)
        if not lookup_symb or not symbol:
            return apology("Stock doesnt exist")
        try:  # checks if the string is a int equivalet
            shares = int(request.form.get("shares"))  # converting it if true
        except ValueError:
            return apology("Invalid share quantity")
        if shares <= 0:  # making sure its not negitive
            return apology("Invaild Share Quantity")
        rows = db.execute(
            "SELECT * FROM purchases WHERE user_id = ? and stock_symbol = ?",
            session["user_id"],
            lookup_symb["symbol"],
        )
        if len(rows) <= 0:
            return apology("you dont own any stock in this compony")
        holding = rows[0]["number_of_shares"]
        if holding < shares:
            return apology("you dont have that many shares to sell ")
        elif holding >= shares:
            value = round(shares * lookup_symb["price"], 2)
            rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            value = round(rows[0]["cash"] + value, 2)
            db.execute(
                "UPDATE users SET cash = ? where id = ?", value, session["user_id"]
            )
            remaining = round(holding - shares, 2)
            type = "SOLD"
            if holding == shares:
                db.execute(
                    "DELETE FROM purchases WHERE user_id = ? and stock_symbol = ?",
                    session["user_id"],
                    lookup_symb["symbol"],
                )
                db.execute(
                    "INSERT INTO transactions (user_id,stock_symbol,number_of_shares,price,type,datetime) VALUES (?,?,?,?,?,datetime('now'))",
                    session["user_id"],
                    lookup_symb["symbol"],
                    shares,
                    lookup_symb["price"],
                    type,
                )
                return redirect("/")
            db.execute(
                "UPDATE purchases SET number_of_shares = ? ,type = 'holding' WHERE user_id = ? and stock_symbol = ?",
                remaining,
                session["user_id"],
                lookup_symb["symbol"],
            )

            db.execute(
                "INSERT INTO transactions (user_id,stock_symbol,number_of_shares,price,type,datetime) VALUES (?,?,?,?,?,datetime('now'))",
                session["user_id"],
                lookup_symb["symbol"],
                shares,
                lookup_symb["price"],
                type,
            )
            return redirect("/")
    else:
        stocks = db.execute(
            "SELECT stock_symbol FROM purchases WHERE user_id = :user_id GROUP BY stock_symbol",
            user_id=session["user_id"],
        )
        return render_template("sell.html", stocks=stocks)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("password and confirmation not same ")
        row = db.execute("SELECT hash from users where id = ?", session["user_id"])
        current_pass = row[0]["hash"]
        if check_password_hash(current_pass, password):
            return apology("password cant be same as previous one")
        hashed_pass = generate_password_hash(password)
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", hashed_pass, session["user_id"]
        )
        flash("Password changed succesfully!")
        return redirect("/")
    else:
        return render_template("password.html")

