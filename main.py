import pymongo
from flask import Flask, request, jsonify
import jwt
import datetime
from pymongo.errors import ServerSelectionTimeoutError
from bson.json_util import dumps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

connected_users = {}
client = pymongo.MongoClient(
    "mongodb+srv://TbowLeder:Codons9876@cluster0.r5zgyhj.mongodb.net/?retryWrites=true&w=majority")

db = client.mario

try:
    client.server_info()
    print("Connexion OK!")
except ServerSelectionTimeoutError as err:
    print(f"Impossible de se connecter à MongoDB: {err}")


def remove_user_tokens(token):
    db.tokens.delete_many({"token": token})


def encode_auth_token(username, remember_me=False):
    """
    Génère le jeton d'authentification JWT en utilisant les informations de l'utilisateur
    :param username:
    :param remember_me:
    :return: string
    """
    try:
        if remember_me:
            expires = datetime.timedelta(days=30)
        else:
            expires = datetime.timedelta(seconds=1)
        payload = {
            'exp': datetime.datetime.utcnow() + expires,
            'iat': datetime.datetime.utcnow(),
            'sub': username
        }
        return jwt.encode(payload, 'codons9876', algorithm='HS256')
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Décode le jeton d'authentification JWT et vérifie s'il est expiré
    :param auth_token:
    :return: dict | string
    """
    try:
        payload = jwt.decode(auth_token, 'codons9876', algorithms='HS256')
        if 'exp' in payload:
            exp_time = datetime.datetime.fromtimestamp(payload['exp'])
            if datetime.datetime.utcnow() > exp_time:
                remove_user_tokens(auth_token)
                return 'Token expired'
        return payload
    except jwt.ExpiredSignatureError:
        remove_user_tokens(auth_token)
        return 'Token expired'
    except jwt.InvalidTokenError:
        return 'Token invalid'


@app.route('/register', methods=['POST'])
def register():
    """Handle user registration"""
    data = request.get_json()
    remember_me = data.get('remember_me', False)
    existing_user = db.users.find_one({"email": data['email']})
    if existing_user:
        return jsonify({'message': 'Email already exists, please login or use another email'}), 400
    auth_token = encode_auth_token(data['username'], remember_me)
    new_user = {
        "firstName": data['firstName'],
        "name": data['name'],
        "username": data['username'],
        "email": data['email'],
        "password": data['password'],
        "tokens": [auth_token]
    }
    db.users.insert_one(new_user)
    return jsonify({'message': 'User registered successfully', 'token': auth_token, 'username': data['username']}), 201


@app.route('/get_user', methods=['POST'])
def get_user():
    data = request.get_json()
    token = data['token']
    check_token = decode_auth_token(token)
    if check_token == 'Token expired' or check_token == 'Token invalid':
        return jsonify({'message': check_token}), 401
    else:
        user = dumps(db.users.find_one({"tokens": token}))

        if user:
            return jsonify({'user': user}), 200
        else:
            return jsonify({'message': 'User not found'}), 404


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = db.users.find_one({"email": data['email'], "password": data['password']})
    if user:
        remember_me = data.get('remember_me', False)
        auth_token = encode_auth_token(user['username'], remember_me)
        # Update the user's token in the database
        db.users.update_one({"email": data['email']}, {"$addToSet": {"tokens": auth_token}})
        return jsonify(
            {'message': 'User logged in successfully', 'token': auth_token, 'username': user['username']}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    token = db.users.find_one({"token": data['token']})
    if token:
        remove_user_tokens(token)
        return jsonify({'message': 'User logout successfully', 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/newPassword', methods=['POST'])
def new_password():
    data = request.get_json()
    email = db.users.find_one({"email": data['email']})
    if email:
        """TOOOOO DOOOOOOOO"""
        return jsonify({'message': 'User logout successfully', 'token': email}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/token', methods=['POST'])
def login_with_token():
    """Handle user login with token"""
    data = request.get_json()
    auth_token = data['token']
    check_token = decode_auth_token(auth_token)
    if check_token == 'Token expired' or check_token == 'Token invalid':
        return jsonify({'message': check_token}), 401
    else:
        user = db.users.find_one({"tokens": auth_token})

        if user:
            return jsonify({'message': 'User logged in successfully', 'username': user['username']}), 200
        else:
            return jsonify({'message': 'Invalid token'}), 401


@app.route("/get_messages", methods=["POST"])
def get_messages():
    data = request.get_json()
    auth_token = data['token']
    check_token = decode_auth_token(auth_token)
    if check_token == 'Token expired' or check_token == 'Token invalid':
        return jsonify({'message': check_token}), 401
    else:
        user = db.users.find_one({"tokens": auth_token})
        if user:
            messages = list(db.conversations.find({"participants_email": user["email"]}))
            i = 0
            while i < len(messages):
                obj = messages[i]
                participants_email = obj['participants_email']
                participants_email.remove(user["email"])
                participants_username = obj['participants_username']
                participants_username.remove(user["username"])
                i += 1
            return jsonify(dumps(messages)), 200
        else:
            return jsonify({'message': 'Invalid token'}), 401


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender_token = data['sender_token']
    recipient_email = data['recipient_email']
    recipient = db.users.find_one({"email": recipient_email})
    recipient_username = recipient["username"]
    user = db.users.find_one({"tokens": sender_token})
    if recipient and user:
        email_sender = user["email"]
        user_name_sender = user["username"]
        message = {"message": data['message'], "user_name_sender": user_name_sender, "imagePath": data["imagePath"]}
        conversations = db.conversations.find_one({"participants_email": [email_sender, recipient_email]})
        if conversations:
            db.conversations.update_one({"participants_email": [email_sender, recipient_email]},
                                        {"$push": {"messages": message}})
        else:
            conversations = db.conversations.find_one({"participants_email": [recipient_email, email_sender]})
            if conversations:
                db.conversations.update_one({"participants_email": [recipient_email, email_sender]},
                                            {"$push": {"messages": message}})
            else:
                participants_email = [email_sender, recipient_email]
                messages = [message]
                conversation = {
                    "participants_username": [recipient_username, user_name_sender],
                    "participants_email": participants_email,
                    "messages": messages,

                }
                db.conversations.insert_one(conversation)

    else:
        return jsonify({'message': "not good"}), 401
    return jsonify({'message': "good man"}), 201


@app.route('/user_list', methods=['GET'])
def user_list():
    data = dumps(db.users.find({}, {"username", "email"},))
    return data


@app.route('/getresto', methods=['GET'])
def getresto():
    data = dumps(db.resto.find({}, {"name", "image"},))
    return jsonify(data)


@app.route('/addresto', methods=['POST'])
def addresto():
    name = request.form.get('name') or request.json.get('name')
    image_file = request.files.get('image')
    date = datetime.datetime.now()
    strDate = str(date.strftime("%Y%m%d%H%M%S%f"))
    if not name or not image_file:
        return jsonify({"error": "Name and Image are required!"}), 400
    if image_file:
        location = f'C:/Users/marti/PycharmProjects/backend_mario/images/{strDate}.jpg'
        image_file.save(location)

    result = db.resto.insert_one({"name": name, "image": strDate})

    return jsonify({"message": "Resto added successfully", "id": str(result.inserted_id)})


if __name__ == '__main__':
    app.run(host="localhost", port=5000)
