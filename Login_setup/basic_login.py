import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
from getpass import getpass
import bcrypt
from email_validator import validate_email, EmailNotValidError

def get_user_from_db(email_id, collection):
    return collection.find_one({"emailid": email_id})

def insert_user_db(user_info, collection):
    return collection.insert_one(user_info)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def valid_email(email):
    try:
        validate_email(email) 
        return True
    except EmailNotValidError as e:
        print(str(e))
        return False


def main():
    try:
        client = pymongo.MongoClient("you host :)", serverSelectionTimeoutMS=5000)
        db = client["test-database"]
        collections = db.userPassword

        # Try to ping the server to ensure the connection works
        client.server_info()

        while True:
            login = input("Type L for login, Type S for sign-up, Type R to reset password or Q to quit: ").upper()

            if login == "L":
                email_id = input("Enter email-id: ")
                password = getpass("Enter password: ")

                user = get_user_from_db(email_id, collections)

                if user and check_password(user["password"], password):
                    print("Login successful")
                else:
                    print("Email id or Password is incorrect")

            elif login == "S":
                email_id = input("Enter email-id: ")
                
                if not valid_email(email_id):
                    print(f"{email_id} is an invalid email address.")
                    continue

                password = getpass("Enter password: ")
                existing_user = get_user_from_db(email_id, collections)

                if existing_user:
                    print("User with this email already exists.")
                else:
                    hashed_password = hash_password(password)
                    userinfo = {
                        "emailid": email_id,
                        "password": hashed_password,
                    }
                    result = insert_user_db(userinfo, collections)
                    print("User registered with ID:", result.inserted_id)
                
            elif login == "R":
                email_id = input("Enter your registered email address: ")
                existing_user = get_user_from_db(email_id, collections)

                if not existing_user:
                    print("You didn't register with your email address")

                else:
                    new_password = getpass("Enter your new password")
                    updated_password = {'$set': {'password': hash_password(new_password)}}
                    collections.update_one({'emailid': email_id}, updated_password)
                    

            elif login == "Q":
                break

    except ServerSelectionTimeoutError:
        print("Failed to connect to the database. Please check your connection.")
    except PyMongoError as e:
        print(f"An error occurred with the database: {e}")

if __name__ == "__main__":
    main()
