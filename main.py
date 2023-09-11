import pymongo
from flask import Flask, request, jsonify, send_from_directory
import jwt
import datetime
from pymongo.errors import ServerSelectionTimeoutError
from bson.json_util import dumps
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)
connected_users = {}
client = pymongo.MongoClient(
    "mongodb+srv://TbowLeder:Codons9876@cluster0.r5zgyhj.mongodb.net/?retryWrites=true&w=majority")

db = client.mario

try:
    client.server_info()
    print("Connexion OK!")
except ServerSelectionTimeoutError as err:
    print(f"Impossible de se connecter à MongoDB: {err}")


@app.before_request
def log_request():
    print(f"{request.method} {request.url}")


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


@app.route('/images/<path:filename>')
def serve_image(filename):
    return send_from_directory('./images/', filename)


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


@socketio.on('connect')
def handle_connect():
    token = request.args.get('token')
    check_tocken = decode_auth_token(token)
    if check_tocken == 'Token expired' or check_tocken == "Token invalid":
        print('error')
    else:
        user = db.users.find_one({"tokens": token})
        if user:
            if token in connected_users:
                print('noon')
                # append the new session to the existing user
                connected_users[token].append(request.sid)
            else:
                print('ok')
                # add the new user to the connected_users
                connected_users[token] = [request.sid]


@socketio.on('disconnect')
def handle_disconnect():
    user_token = request.args.get('token')
    if user_token in connected_users:
        del connected_users[user_token]



@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender_token = data['sender_token']
    recipient_email = data['recipient_email']
    recipient = db.users.find_one({"email": recipient_email})
    recipient_username = recipient["username"]
    user = db.users.find_one({"tokens": sender_token})
    if recipient and user:
        tokens_recipient = recipient["tokens"]
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

        for token in tokens_recipient:
            if token in connected_users:
                recipient_sid = connected_users[token]
                # socketio.emit('new_message', {'sender': sender_token, 'message': message}, room=recipient_sid)
    else:
        return jsonify({'message': "not good"}), 401
    return jsonify({'message': "good man"}), 201


@app.route('/user_list', methods=['GET'])
def user_list():
    data = dumps(db.users.find({}, {"username", "email"},))
    return data

@app.route('/getresto', methods=['GET'])
def getresto():
    data = dumps(db.resto.find({},{"name","image"},))
    return jsonify(data)
@app.route('/addresto', methods=['POST'])
def addresto():
    # Récupération des données du formulaire ou d'une requête JSON
    name = request.form.get('name') or request.json.get('name')
    image = request.form.get('image') or request.json.get('image')

    # Vérification des données
    if not name or not image:
        return jsonify({"error": "Name and Image are required!"}), 400

    # Insertion des données dans la collection 'resto'
    result = db.resto.insert_one({"name": name, "image": image})

    # Renvoie une réponse avec l'ID du nouveau document inséré
    return jsonify({"message": "Resto added successfully", "id": str(result.inserted_id)})

@app.route('/user_descriptor', methods=['POST'])
def user_descriptor():
    data = request.get_json()
    filename = data['filename']
    xR = data['xR']
    xG = data['xG']
    xB = data['xB']
    myFileR = open("user_descriptor/" + 'R' + filename, "w+")
    myFileR.write(str(xR))
    myFileR.close()

    myFileG = open("user_descriptor/" + 'G' + filename, "w+")
    myFileG.write(str(xG))
    myFileG.close()

    myFileB = open("user_descriptor/" + 'B' + filename, "w+")
    myFileB.write(str(xB))
    myFileB.close()

    return jsonify({'message': "good man"}), 201


@app.route('/get_user_descriptor', methods=['POST'])
def get_user_descriptor():
    data = request.get_json()
    filename = data['filename']

    myFileR = open("user_descriptor/" + 'R' + filename, "r")
    xR = str(myFileR.read())
    myFileR.close()

    myFileG = open("user_descriptor/" + 'G' + filename, "r")
    xG = str(myFileG.read())
    myFileG.close()

    myFileB = open("user_descriptor/" + 'B' + filename, "r")
    xB = str(myFileB.read())
    myFileB.close()
    return jsonify({'xR': xR, 'xG': xG, 'xB': xB}), 201


if __name__ == '__main__':
    socketio.run(app,host="127.0.0.1",port=5000)
