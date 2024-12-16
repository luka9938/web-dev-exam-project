import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bottle import default_app, put, delete, get, post, request, response, run, static_file, template
import x, re
from icecream import ic
import bcrypt
import json
import credentials
import uuid
import random
import string
from send_email import send_verification_email
import os
import time
import sqlite3

def generate_verification_code():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

sessions = {}

def validate_user_logged():
    user_session_id = request.get_cookie("user_session_id")
    if user_session_id in sessions:
        return True
    else:
        return False
    
def validate_user_role():
    user_role = request.get_cookie("role")
    if user_role == "partner":
        return True
    elif user_role == "customer":
        return False
    
    return False

def validate_admin():
    user_role = request.get_cookie("role")
    if user_role == "admin":
        return True
    else:
        return False

def validate_customer():
    user_role = request.get_cookie("role")
    if user_role == "customer":
        return True
    else:
        return False
        

##############################
@get("/app.css")
def _():
    return static_file("app.css", ".")


##############################
@get("/<file_name>.js")
def _(file_name):
    return static_file(file_name+".js", ".")

##############################
@get("/images/<item_splash_image>")
def serve_image(item_splash_image):
    # Check if the requested image exists in the current directory
    if os.path.exists(os.path.join("images", item_splash_image)):
        # Serve the requested image from the current directory
        return static_file(item_splash_image, "images")
    else:
        # Serve the image from the uploads directory if it's not found in the current directory
        return static_file(item_splash_image, root="uploads/images")

##############################
@get("/")
def home():
    try:
        x.setup_database()
        # Fetch items from the ArangoDB collection 'items'
        conn = x.db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM items ORDER BY item_created_at LIMIT ?", (x.ITEMS_PER_PAGE,))
        items = cursor.fetchall()
        conn.close()
        is_logged = validate_user_logged()
        is_role = validate_user_role()
        is_admin_role = validate_admin()

        return template("index.html", items=items, mapbox_token=credentials.mapbox_token, is_logged=is_logged, is_role=is_role, is_admin_role=is_admin_role)
    except Exception as ex:
        ic(ex)
        return str(ex)
    finally:
        pass
##############################
@get("/signup")
def _():
    try:
        is_logged = validate_user_logged()
        print("user is logged in?: ")
        print(is_logged)
        is_role = validate_user_role()
        print("is user a partner?: ")
        print(is_role)
        is_admin_role = validate_admin()
        return template("signup_wu_mixhtml.html", is_logged=is_logged,is_role=is_role, is_admin_role=is_admin_role)
    except Exception as ex:
        print("there was a problem loading the page")
        print(ex)
        return ex
    finally:
        pass
##############################
@post("/signup")
def _():
    try:
        # Validate username, email, and password
        username = x.validate_user_username()
        email = x.validate_email()
        password = x.validate_password()
        
        # Generate verification code
        verification_code = generate_verification_code()
        
        # Get selected option (role)
        selected_option = request.forms.get("option")
        
        # Check if user already exists
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_email = ?", (email,))
            existing_user = cursor.fetchone()
        
        if existing_user:
            return "User already exists"
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create user dictionary
        user = {
            "username": username, 
            "user_email": email, 
            "user_password": hashed_password.decode('utf-8'), 
            "role": selected_option, 
            "verification_code": verification_code, 
            "verified": False,
            "is_deleted": False
        }
        
        # Insert user into the database
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, user_email, user_password, role, verification_code, verified, is_deleted) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user["username"], user["user_email"], user["user_password"], user["role"], 
                  user["verification_code"], user["verified"], user["is_deleted"]))
            conn.commit()
        
        # Send verification email
        send_verification_email(email, verification_code)
        
        # Redirect to login page
        response.status = 303
        response.set_header('Location', '/login')
    except Exception as ex:
        ic(ex)
        if "user_name" in str(ex):
            return f"""
            <template mix-target="#message">
                {ex.args[1]}
            </template>
            """            
    finally:
        pass
##############################
@get("/verify")
def verify():
    try:
        verification_code = request.query.code
        res = {
            "query": "FOR user IN users FILTER user.verification_code == :code RETURN user",
            "bindVars": {"code": verification_code}
        }
        query_result = x.db(res)
        users = query_result.get("result", [])

        if not users:
            return "Invalid verification code"
        
        user = users[0]
        user["verified"] = True
        update_res = {
            "query": "UPDATE :user WITH {verified: true} IN users RETURN NEW",
            "bindVars": {"user": user}
        }
        x.db(update_res)

        return "You email has been verified. You can now log in at <a href='/login'>Login</a>."
    except Exception as ex:
        print("An error occurred:", ex)
        return "An error occurred while verifying your email."
    finally:
        pass
##############################
@post("/users")
def create_user():
    try:
        username = x.validate_user_username()  # Validation of username using method from x.py file
        email = x.validate_email()  # Validation of email using method from x.py file
        ic(username)  # This is ice cream it displays error codes when something goes wrong
        ic(email)  # This is ice cream it displays error codes when something goes wrong
        
        # Insert user into SQLite database
        db_conn = x.db()
        cursor = db_conn.cursor()
        cursor.execute("INSERT INTO users (username, email) VALUES (?, ?)", (username, email))
        db_conn.commit()
        db_conn.close()

        return "User created successfully"
    except Exception as ex:
        ic(ex)
        if "username" in str(ex):
            return f"""
            <template mix-target="#message">
                {ex.args[1]}
            </template>
            """
    finally:
        if "db" in locals(): x.db.close()


##############################
@get("/items/page/<page_number>")
def _(page_number):
    try:
        page_number = int(page_number)
        if page_number < 1:
            raise ValueError("Page number must be greater than 0")
        
        offset = (page_number - 1) * x.ITEMS_PER_PAGE
        conn = x.db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM items ORDER BY item_created_at LIMIT ? OFFSET ?", (x.ITEMS_PER_PAGE, offset))
        items = cursor.fetchall()
        conn.close()
        ic(items)

        html = ""
        is_logged = False
        try:
            x.validate_user_logged()
            is_logged = True
        except:
            pass
        
        is_admin_role = validate_admin()
        for item in items:
            html += template("_item", item=item, is_logged=is_logged, is_admin_role=is_admin_role)
        
        next_page = page_number + 1
        btn_more = template("__btn_more", page_number=next_page)
        if len(items) < x.ITEMS_PER_PAGE:
            btn_more = ""

        return f"""
        <template mix-target="#items" mix-bottom>
            {html}
        </template>
        <template mix-target="#more" mix-replace>
            {btn_more}
        </template>
        <template mix-function="test">{json.dumps(items)}</template>
        """
    except Exception as ex:
        ic(ex)
        return "ups..."
    finally:
        pass


##############################
@get("/login")
def login_post():
    try:
        user_email = request.forms.get("user_email")
        user_password = request.forms.get("user_password")

        is_role = validate_user_role()
        is_admin_role = validate_admin()

        conn = x.db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_email = ?", (user_email,))
        users = cursor.fetchall()
        print("Users found:", users)  # Add this line for debugging
        conn.close()

        if users:
            for user in users:
                if user["verified"]:
                    stored_hashed_password = user["user_password"]
                    if bcrypt.checkpw(user_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                        user_session_id = str(uuid.uuid4())
                        sessions[user_session_id] = user
                        response.set_cookie("user_session_id", user_session_id)
                        response.set_cookie("role", user["role"], secret=x.COOKIE_SECRET)
                        response.set_cookie("user_id", user["user_id"], secret=x.COOKIE_SECRET)
                        response.set_cookie("user_email", user_email, secret=x.COOKIE_SECRET)
                        response.status = 303
                        response.set_header('Location', '/')
                        return
                    else:
                        error_message = "Your password is wrong"
                        return template("login_wu_mixhtml.html", error_message=error_message, is_role=is_role, is_admin_role=is_admin_role)
                else:
                    error_message = "Only verified users can login"
                    return template("login_wu_mixhtml.html", error_message=error_message, is_role=is_role, is_admin_role=is_admin_role)
        else:
            error_message = "Incorrect email or password"
            return template("login_wu_mixhtml.html", error_message=error_message, is_role=is_role, is_admin_role=is_admin_role)
    except Exception as ex:
        print("An error occurred:", ex)
        return "An error occurred while processing your request"
    finally:
        if "db" in locals(): x.db.close()


##############################
@get("/profile")
def profile():
    try:
        user_session_id = request.get_cookie("user_session_id")
        if not user_session_id:
            response.status = 303
            response.set_header('Location', '/login')
            return

        if user_session_id not in sessions:
            response.status = 303
            response.set_header('Location', '/login')
            return

        user = sessions[user_session_id]
        is_role = validate_user_role()
        is_logged = validate_user_logged()
        is_admin_role = validate_admin()

        conn = sqlite3.connect("x.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user['user_id'],))
        user_data = cursor.fetchone()
        conn.close()

        if not user_data:
            return "User not found"

        user_data = {
            'user_id': user_data[0],
            'username': user_data[1],
            'user_email': user_data[2],
            'user_password': user_data[3]
        }

        success_message = request.get_cookie("success_message")
        response.delete_cookie("success_message", path='/')

        return template("user_profile", user=user_data, is_role=is_role, is_logged=is_logged, is_admin_role=is_admin_role, success_message=success_message)
    except Exception as ex:
        print("An error occurred:", ex)
        return {"error": str(ex)}
    finally:
        if "db" in locals(): x.db.close()

##############################

@post("/update_profile")
def update_profile():
    try:
        user_session_id = request.get_cookie("user_session_id")
        if user_session_id not in sessions:
            response.status = 303
            response.set_header('Location', '/login')
            return
        
        user = sessions[user_session_id]

        username = request.forms.get("user_name")    
        user_email = request.forms.get("user_email")
        user_password = request.forms.get("user_password")

        if user_password:
            hashed_password = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        else:
            hashed_password = user["user_password"]

        user["username"] = username
        user["user_email"] = user_email
        user["user_password"] = hashed_password

        conn = sqlite3.connect("x.db")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET username = ?, user_email = ?, user_password = ?
            WHERE user_id = ?
        """, (username, user_email, hashed_password, user["user_id"]))
        conn.commit()
        conn.close()

        sessions[user_session_id] = user
        response.set_cookie("success_message", "Profile changed successfully", path='/')
        response.status = 303
        response.set_header('Location', '/profile')
        return
    except Exception as ex:
        ic(ex)
        return str(ex)
    finally:
        pass
##############################
@get("/partner_properties")
def get_partner_properties():
    try:
        is_logged = validate_user_logged()
        validate_user_role()

        active_user = request.get_cookie("user_id")
        if not active_user:
            return "User ID not found in cookies"

        # Query to fetch user's items from SQLite
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM items WHERE user_id = ?", (active_user,))
            your_items = cursor.fetchall()

        # Render HTML template with retrieved items
        is_admin_role = validate_admin()
        return template("partner_items.html", your_items=your_items, is_logged=is_logged, is_admin_role=is_admin_role)

    except Exception as ex:
        # Handle any exceptions
        print("An error occurred:", ex)
        return str(ex)
    finally:
        if "db" in locals(): x.db.close()
    
##############################
@post("/delete_item/<item_id>")
def delete_item(item_id):
    try:
        delete_query = {
            "query": "REMOVE { _key: :key } FROM items",
            "bindVars": {"key": item_id}
        }
        result = x.db(delete_query)

        if result["error"]:
            return "Error deleting item"
        else:
            response.status = 303 
            response.set_header('Location', '/partner_properties')
            return

    except Exception as ex:
        # Handle any exceptions
        return str(ex)

##############################
@post("/verification_email_delete")
def send_verification_email_delete():
    try:
        user_email = request.forms.get("user_email")
        print(user_email)
        user_password = request.forms.get("user_password")
        print(user_password)
        sender_email = "joeybidenisbased@gmail.com"
        password = "tdvi euik qgsa bzdf"

        message = MIMEMultipart("alternative")
        message["Subject"] = "Verify deletion of you account"
        message["From"] = sender_email
        message["To"] = user_email


        text = f"""\
        Hi,
        Please verify deletion of your account by clicking the link
        """
        html = f"""\
        <html>
        <body>
            <p>Hi,<br>
            Please verify deletion of your account by clicking the link below:<br>
            <a href="http://127.0.0.1/Verify_delete?code={user_email}">Delete account</a>
            </p>
        </body>
        </html>
        """

        # Turn these into plain/html MIMEText objects
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")

        # Add HTML/plain-text parts to MIMEMultipart message
        # The email client will try to render the last part first
        message.attach(part1)
        message.attach(part2)

        # Create secure connection with server and send email
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, user_email, message.as_string())
        response.status = 303
        response.set_header('Location', '/')
        return
    except Exception as ex:
        print(ex)
        return ex
    finally:
        pass
    
##############################
@get("/Verify_delete")
def login_post():
    
    try:
        verification_code = request.query.code

        conn = sqlite3.connect("x.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE verification_code = ?", (verification_code,))
        user = cursor.fetchone()

        if not user:
            return "Verification failed. The user with this verification code does not exist."

        # Mark the user as deleted in the database
        cursor.execute("UPDATE users SET is_deleted = 1 WHERE verification_code = ?", (verification_code,))
        conn.commit()
        conn.close()

        return "You account has been deleted. You can go back to the homepage now <a href='/'>Homepage</a>."
        # return "login failed - incorrect email or password"
    except Exception as ex:
        print("An error occurred:", ex)
        return "An error occurred while processing your request"

##############################
@get("/logout")
def _():
    user_session_id = request.get_cookie("user_session_id")
    if user_session_id in sessions:
        del sessions[user_session_id]
    response.delete_cookie("user_session_id")
    response.delete_cookie("role")
    response.status = 303
    response.set_header('Location', '/')
    return

@get("/rooms/<id>")
def _(id):
    try:

        conn = sqlite3.connect("x.db")
        cursor = conn.cursor()
        cursor.row_factory = sqlite3.Row  # To access columns by name
        cursor.execute("SELECT * FROM items WHERE item_pk = ?", (id,))
        item = cursor.fetchone()

        conn.close()

        # If item is not found, return 404 error
        if not item:
            response.status = 404
            return {"error": "Item not found"}

        # Convert sqlite3.Row to a dict
        item_dict = dict(item)

        # Calculate formatted price
        price = int(item_dict["item_price_per_night"])
        formatted_price = "{:,.0f}".format(price).replace(",", ".")

        # Prepare data for template rendering
        title = f"Item {id}"
        is_logged = validate_user_logged()
        is_role = validate_user_role()
        is_admin_role = validate_admin()
        is_customer_role=validate_customer()

        # Render the template with the retrieved item and other data
        return template("rooms",
                        id=id,
                        title=title,
                        item=item_dict,
                        formatted_price=formatted_price,
                        is_logged=is_logged,
                        is_role=is_role,
                        is_admin_role=is_admin_role,
                        is_customer_role=is_customer_role)
    except Exception as ex:
        print("An error occurred:", ex)
        return {"error": str(ex)}
    finally:
        if "db" in locals(): x.db.close()

##############################
@delete("/users/<key>")
def delete_user(key):
    try:
        # Validate key format
        if not key.isdigit():
            return "Invalid key format"

        # Log the user key
        ic(key)

        # Construct and execute SQL query to delete user from SQLite database
        query = "DELETE FROM users WHERE user_pk = ?"
        x.db.execute(query, (key,))
        x.db.commit()

        # Log the result of the deletion
        ic("User deleted successfully")

        # Retrieve user email before deletion for sending block email
        user_email_query = "SELECT user_email FROM users WHERE user_pk = ?"
        result = x.db.execute(user_email_query, (key,))
        user_email = result.fetchone()["user_email"]

        # Send block email
        x.send_block_email(user_email)

        # Return success message
        return f"""
        <template mix-target="[id='{key}']" mix-replace>
            <div class="mix-fade-out user_deleted" mix-ttl="2000">User blocked</div>
        </template>
        """

    except Exception as ex:
        # Handle any exceptions
        ic(ex)
        return "An error occurred"
    finally:
        if "db" in locals(): x.db.close()

##############################

@get("/forgot-password")
def forgot_password():
    try:
        is_logged = validate_user_logged()
        print("user is logged in?: ")
        print(is_logged)
        is_role = validate_user_role()
        print("is user a partner?: ")
        print(is_role)
        is_admin_role = validate_admin()
        return template("forgot-password.html",is_logged=is_logged, is_role=is_role, is_admin_role=is_admin_role)
    except Exception as ex:
        ic(ex)
    finally:
        pass
    

##############################
@post("/forgot-password")
def handle_forgot_password():
    try:
        email = request.forms.get("email")

        # Query user from SQLite database
        user_query = "SELECT * FROM users WHERE user_email = ?"
        result = x.db.execute(user_query, (email,))
        user = result.fetchone()

        if not user:
            raise Exception("Email not found")

        # Extract user data and send reset email
        user_pk = user["user_pk"]
        x.send_reset_email(email, user_pk)

        return "Password reset email sent"
    except Exception as ex:
        ic(ex)
        return str(ex)
    finally:
        if "db" in locals(): x.db.close()
    
##############################
@get("/reset-password/<key>")
def reset_password(key):
    try:
        db_conn = x.db()
        cursor = db_conn.cursor()

        cursor.execute("SELECT * FROM users WHERE _key = ?", (key,))
        user = cursor.fetchone()
        
        db_conn.close()

        if not user:
            response.status = 404
            return {"error": "User not found"}
        
        return template("reset-password.html", key=key, user=user)
    except Exception as ex:
        return str(ex)
    finally:
        if "db" in locals(): x.db.close()

##############################
@put("/reset-password/<key>")
def handle_reset_password(key):
    try:
        password = request.forms.get("password")
        confirm_password = request.forms.get("confirm_password")

        if password != confirm_password:
            return "Passwords do not match"
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update user's password in SQLite database
        update_query = "UPDATE users SET user_password = ? WHERE user_pk = ?"
        x.db.execute(update_query, (hashed_password, key))
        x.db.commit()

        return "Password reset successfully"
    except Exception as ex:
        ic(ex)
        return str(ex)
    finally:
        if "db" in locals(): x.db.close()

##############################
@put("/users/unblock/<key>")
def unblock_user(key):
    try:
        # Regex validation for key
        if not re.match(r'^[1-9]\d*$', key):
            return "Invalid key format"

        # Update user's blocked status in SQLite database
        update_query = "UPDATE users SET blocked = 0 WHERE user_pk = ?"
        x.db.execute(update_query, (key,))
        x.db.commit()

        # Fetch user's email
        user_query = "SELECT user_email FROM users WHERE user_pk = ?"
        user_email = x.db.execute(user_query, (key,)).fetchone()[0]
        x.send_unblock_email(user_email)

        return f"""
        <template mix-target="[id='{key}']" mix-replace>
            <div class="mix-fade-out user_unblocked" mix-ttl="2000">User unblocked</div>
        </template>
        """
    except Exception as ex:
        ic(ex)
        return "An error occurred"
    finally:
        if "db" in locals(): x.db.close()

##############################
UPLOAD_DIR = "uploads/images"
##############################
@get("/add_item")
def add_item_form():
    try:
        is_logged = validate_user_logged()
        print("user is logged in?: ")
        print(is_logged)
        is_role = validate_user_role()
        print("is user a partner?: ")
        print(is_role)
        is_admin_role = validate_admin()
        return template("add_item.html", is_logged=is_logged, is_role=is_role, is_admin_role=is_admin_role)
    except Exception as ex:
        print("There was a problem loading the page:", ex)
        return str(ex)
##############################
@post("/add_item")
def add_item():
    try:
        item_user = request.get_cookie("user_id")
        item_email = request.get_cookie("user_email")
        # Get form data
        item_name = request.forms.get("item_name")
        
        # Generate random values for latitude, longitude, and stars
        item_lat = round(random.uniform(55.65, 55.7), 4)
        item_lon = round(random.uniform(12.55, 12.6), 4)
        item_stars = round(random.uniform(3.0, 5.0), 1)
        
        item_price_per_night = request.forms.get("item_price_per_night")

        # Process splash image
        item_splash_image = request.files.get("item_splash_image")

        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)

        # Generate random filename for splash image
        splash_image_filename = f"{x.generate_random_string()}_{item_splash_image.filename}"
    
        splash_image_path = os.path.join(UPLOAD_DIR, splash_image_filename)
        item_splash_image.save(splash_image_path)

        # Process additional images
        image2 = request.files.get("image2")
        image2_filename = f"{x.generate_random_string()}_{image2.filename}"
        image2_path = os.path.join(UPLOAD_DIR, image2_filename)
        image2.save(image2_path)
        
        image3 = request.files.get("image3")
        image3_filename = f"{x.generate_random_string()}_{image3.filename}"
        image3_path = os.path.join(UPLOAD_DIR, image3_filename)
        image3.save(image3_path)

        # Create item data
        item = {
            "item_name": item_name,
            "item_splash_image": splash_image_filename,
            "item_lat": item_lat,
            "item_lon": item_lon,
            "item_stars": item_stars,
            "item_price_per_night": int(item_price_per_night),
            "item_created_at": int(time.time()),
            "item_updated_at": 0,
            "item_image2": image2_filename,
            "item_image3": image3_filename,
            "item_user": item_user,
            "item_email": item_email

        }

        # Save item to the database
        insert_query = """
        INSERT INTO items 
        (item_name, item_splash_image, item_lat, item_lon, item_stars, item_price_per_night,
        item_created_at, item_updated_at, item_image2, item_image3, item_user, item_email) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        x.db.execute(insert_query, (item["item_name"], item["item_splash_image"], item["item_lat"],
                                    item["item_lon"], item["item_stars"], item["item_price_per_night"],
                                    item["item_created_at"], item["item_updated_at"], item["item_image2"],
                                    item["item_image3"], item["item_user"], item["item_email"]))
        x.db.commit()
        response.status = 303
        response.set_header('Location', '/partner_properties')
        return
    except Exception as ex:
        print("An error occurred:", ex)
        return f"An error occurred: {str(ex)}"
    finally:
        if "db" in locals(): x.db.close()
##############################
@get('/edit_item/<key>')
def edit_item_form(key):
    try:
        user_id = x.validate_logged()
        x.validate_user_role()
        db_conn = x.db()
        cursor = db_conn.cursor()

        cursor.execute("SELECT * FROM items WHERE _key = ?", (key,))
        item = cursor.fetchone()

        db_conn.close()

        if not item:
            response.status = 404
            return {"error": "Item not found"}

        title = f"Edit your property"
        return template("edit_item", key=key, title=title, item=item)
    except Exception as ex:
        return str(ex)
    finally:
        if "db" in locals(): x.db.close()

##############################
@post('/edit_item/<key>')
def update_item(key):
    try:
        item_name = request.forms.get('item_name')
        item_price_per_night = request.forms.get('item_price_per_night')
        
        item_splash_image = request.files.get('item_splash_image')
        image2 = request.files.get('image2')
        image3 = request.files.get('image3')

        db_conn = x.db()
        cursor = db_conn.cursor()

        cursor.execute("SELECT * FROM items WHERE _key = ?", (key,))
        item = cursor.fetchone()
        if not item:
            response.status = 404
            return {"error": "Item not found"}

        # Process splash image
        splash_image_filename = item['item_splash_image']
        if item_splash_image and item_splash_image.filename:
            splash_image_filename = f"{x.generate_random_string()}_{item_splash_image.filename}"
            splash_image_path = os.path.join(UPLOAD_DIR, splash_image_filename)
            item_splash_image.save(splash_image_path)
            # Delete old image
            if item['item_splash_image']:
                old_image_path = os.path.join(UPLOAD_DIR, item['item_splash_image'])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)

        # Process additional images
        image2_filename = item['item_image2']
        if image2 and image2.filename:
            image2_filename = f"{x.generate_random_string()}_{image2.filename}"
            image2_path = os.path.join(UPLOAD_DIR, image2_filename)
            image2.save(image2_path)
            # Delete old image
            if item['item_image2']:
                old_image_path = os.path.join(UPLOAD_DIR, item['item_image2'])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)

        image3_filename = item['item_image3']
        if image3 and image3.filename:
            image3_filename = f"{x.generate_random_string()}_{image3.filename}"
            image3_path = os.path.join(UPLOAD_DIR, image3_filename)
            image3.save(image3_path)
            # Delete old image
            if item['item_image3']:
                old_image_path = os.path.join(UPLOAD_DIR, item['item_image3'])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)

        cursor.execute("""
            UPDATE items SET 
            item_name = ?, 
            item_price_per_night = ?, 
            item_splash_image = ?, 
            item_image2 = ?, 
            item_image3 = ? 
            WHERE _key = ?
            """, (item_name, item_price_per_night, splash_image_filename, image2_filename, image3_filename, key))
        db_conn.commit()
        
        db_conn.close()

        response.status = 303
        response.set_header('Location', '/partner_properties')
        return
    except Exception as ex:
        return {"error": str(ex)}
    finally:
        if "db" in locals(): x.db.close()


##############################
@post("/block_item/<key>")
def block_item(key):
    try:
        ic(key)
        
        # Toggle the 'blocked' property of the item
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT blocked FROM items WHERE item_pk = ?", (key,))
            result = cursor.fetchone()
            if not result:
                return "Item not found"

            current_blocked_status = result[0]
            new_blocked_status = not current_blocked_status
            cursor.execute("UPDATE items SET blocked = ? WHERE item_pk = ?", (int(new_blocked_status), key))
            conn.commit()

        item_email = None
        # Check if the item_email column exists
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(items)")
            columns = cursor.fetchall()
            if any(column[1] == 'item_email' for column in columns):
                cursor.execute("SELECT item_email FROM items WHERE item_pk = ?", (key,))
                result = cursor.fetchone()
                if result:
                    item_email = result[0]
        
        # Send email based on the item's blocked status, if item_email exists
        if item_email:
            if new_blocked_status:
                x.send_block_property_email(item_email)
            else:
                x.send_unblock_property_email(item_email)

        response.status = 303
        response.set_header('Location', '/')
        return
    except Exception as ex:
        ic(ex)
        return "An error occurred"
    finally:
        if "db" in locals(): x.db.close()


##############################
# BOOKING
#If you're getting "/toggle_booking not found", try restarting the server 
@post("/toggle_booking")
def toggle_booking():
    try:
        item_pk = request.forms.get("item_pk")
        
        # Fetch the current booking status
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_booked FROM items WHERE item_pk = ?", (item_pk,))
            result = cursor.fetchone()
            if result is None:
                return "Item not found"

            current_booking_status = result[0]
        
        # Toggle the booking status
        new_booking_status = not current_booking_status
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE items SET is_booked = ? WHERE item_pk = ?", (new_booking_status, item_pk))
            conn.commit()

        # Fetch updated item
        with sqlite3.connect("x.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM items WHERE item_pk = ?", (item_pk,))
            updated_item = cursor.fetchone()

        if updated_item is None:
            return "Updated item not found"

        # Construct the item dictionary
        item_dict = {
            'item_pk': updated_item[0],
            'item_name': updated_item[1],
            'item_splash_image': updated_item[2],
            'item_lat': updated_item[3],
            'item_lon': updated_item[4],
            'item_stars': updated_item[5],
            'item_price_per_night': updated_item[6],
            'item_created_at': updated_item[7],
            'item_updated_at': updated_item[8],
            'blocked': updated_item[9],
            'is_booked': updated_item[10]
        }

        is_role = validate_user_role()
        is_logged = validate_user_logged()
        is_admin_role = validate_admin()

        # Pass necessary data to the template
        return template("rooms", id=item_pk, title=f"Item {item_pk}", item=item_dict, is_role=is_role, is_admin_role=is_admin_role, is_logged=is_logged, formatted_price=updated_item[6])
    except Exception as ex:
        print("An error occurred:", ex)
        return str(ex)
    finally:
        if "db" in locals(): x.db.close()

#############################
try:
    import production
    application = default_app()
except:
    run(host="0.0.0.0", port=80, debug=True, reloader=True, interval=0)