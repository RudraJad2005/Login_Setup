from flask import Flask, request, jsonify
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, ServerSelectionTimeoutError
import bcrypt
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)

# MongoDB connection details (consider using environment variables for security)
MONGO_URI = "You host :)"
DATABASE_NAME = "user_auth"

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DATABASE_NAME]
    users_collection = db.users
except ServerSelectionTimeoutError:
    print("Failed to connect to the database. Please check your connection.")
    exit(1)


def get_user(email):
    """Fetches a user document from the database based on email address.

    Args:
        email (str): The email address of the user to find.

    Returns:
        dict | None: A dictionary containing user information if found, otherwise None.
    """
    return users_collection.find_one(
        {
            "email": email
        }
    )


def create_user(user_data):
    """Creates a new user document in the database.

    Args:
        user_data (dict): A dictionary containing user information (email and hashed password).

    Returns:
        dict: A dictionary containing a success message and the generated user ID.
    """
    try:
        result = users_collection.insert_one(user_data)
        return {
            "message": "User registered", "user_id": str(result.inserted_id)
        }
    except DuplicateKeyError:
        return jsonify(
            {"error": "User with this email already exists"}
        ), 409


def hash_password(password):
    """Hashes a plain text password using bcrypt."""
    return bcrypt.hashpw(
        password.encode(
            'utf-8'
        ), bcrypt.gensalt()
    )


def check_password(stored_password, provided_password):
    """Verifies a provided password against a stored hashed password."""
    return bcrypt.checkpw(
        provided_password.encode(
            'utf-8'
        ), stored_password
    )


def validate_email_address(email):
    """Validates an email address format using the email_validator library."""
    try:
        validate_email(email)
        return True
    except EmailNotValidError as e:
        print(f"Invalid email format: {str(e)}")
        return False

@app.route('/login', methods=['POST'])
def login():

    """Handles user login requests.
        Excepts a JSON payload containing email and password. fields.
    """
    login_data = request.json
    email = login_data.get('email')
    password = login_data.get('password')

    if not email or not password:
        return jsonify(
            {"error": "Email and password are required."}
        ), 400
    
    user = get_user(email)
    if user and check_password(
        user['password'], password
    ):
        return jsonify(
            {
                "message": "Login successful",
                "token": "your_generated_token"
            }
        ), 200
    else:
        return jsonify(
            {
                "error": "Invalid email or password"
            }
        ), 401
    
@app.route('/signup', methods=['POST'])
def signup():
    """Handles user signup requests.

    Expects a JSON payload containing email and password fields.
    """

    signup_data = request.json
    email = signup_data.get('email')
    password = signup_data.get('password')

    if not email or not password:
        return jsonify(
            {
                "error": "Email or password is required."
            }
       ), 400
    
    hashed_password = hash_password(password)
    user_data = {
        "email": email,
        "password": hashed_password,
    }
    result = create_user(user_data)
    return result

if __name__ == "__main__":
    app.run(debug=True)
