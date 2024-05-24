from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import hashlib
import uuid
import threading
import os
import json
import jwt
import datetime

app = Flask(__name__)
api = Api(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Пам’ять для ресурсів у пам’яті
resources = []

# Завантажити користувача база даних із файлу, якщо вона існує
if os.path.exists('users_database.json'):
    with open('users_database.json', 'r') as f:
        users_database = json.load(f)
else:
    users_database = {}

@app.route('/')
def index():
    return 'Ласкаво просимо до API реєстрації користувачів!'

@app.route('/resources', methods=['POST'])
def create_resource():
    data = request.get_json()
    resource_id = len(resources) + 1
    new_resource = {'id': resource_id, 'data': data}
    resources.append(new_resource)
    return jsonify(new_resource), 201

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Page not found'}), 404

class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        salt = uuid.uuid4().hex
        hashed_password = hashlib.sha256(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
        users_database[username] = {
            'salt': salt,
            'hashed_password': hashed_password
        }
        with open('users_database.json', 'w') as f:
            json.dump(users_database, f)
        response = {
            'username': username,
            'message': 'User successfully created'
        }
        return jsonify(response), 201

api.add_resource(UserRegistration, '/register')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400
    if username not in users_database:
        return jsonify({'message': 'User not found'}), 404
    stored_salt = users_database[username]['salt']
    stored_hashed_password = users_database[username]['hashed_password']
    if hashlib.sha256(password.encode('utf-8') + stored_salt.encode('utf-8')).hexdigest() != stored_hashed_password:
        return jsonify({'message': 'Incorrect password'}), 401
    # Generate JWT token
    access_token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    refresh_token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)}, app.config['SECRET_KEY'])
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200

def run_flask():
    app.run()

flask_thread = threading.Thread(target=run_flask)
flask_thread.start()

def hash_password(password):
    salt = hashlib.sha256(os.urandom(32)).hexdigest().encode('ascii')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + hashed_password

def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    hashed_password = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return hashed_password == stored_password

stored_password = None
while True:
    cmd = input("Введіть команду: ")
    if cmd.lower() == 'exit':
        if stored_password:
            users_database['stored_password'] = stored_password.decode('ascii')
            with open('users_database.json', 'w') as f:
                json.dump(users_database, f)
        break
    elif cmd.lower() == 'встановити пароль':
        provided_password = input("Будь ласка, введіть свій пароль:")
        stored_password = hash_password(provided_password)
        print("Пароль збережено!")
    elif cmd.lower() == 'authenticate':
        username = input("Введіть своє ім'я користувача: ")
        provided_password = input("Введіть свій пароль: ")
        if username not in users_database:
            print("Користувача не знайдено. Створення нового користувача...")
            provided_password = input("Будь ласка, введіть свій пароль: ")
            stored_password = hash_password(provided_password)
            users_database[username] = {'salt': stored_password[:64], 'hashed_password': stored_password[64:]}
            print("Користувач успішно зареєстрований!")
        else:
            stored_salt = users_database[username]['salt']
            stored_hashed_password = users_database[username]['hashed_password']
            if verify_password(stored_salt + stored_hashed_password, provided_password):
                print("Автентифікація успішна!")
            else:
                print("Неправильний пароль. Помилка автентифікації.")
    else:
        print(f"Команда '{cmd}' не розпізнана. Введіть 'exit', щоб вийти.")
        
