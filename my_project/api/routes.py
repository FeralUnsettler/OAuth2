from flask import Blueprint, request, jsonify, redirect, url_for
from models import User, db
from oauth import get_google_provider_cfg, get_google_token, get_user_info, get_github_provider_cfg, get_github_token, get_facebook_provider_cfg, get_facebook_token
import os

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/login/<provider>', methods=['GET'])
def login(provider):
    if provider == 'google':
        google_provider_cfg = get_google_provider_cfg()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]

        request_uri = requests.Request(
            'GET',
            authorization_endpoint,
            params={
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),
                "scope": "openid email profile",
                "response_type": "code",
                "state": os.urandom(24).hex(),
                "nonce": os.urandom(24).hex()
            }
        ).prepare().url

        return jsonify({"url": request_uri})

    elif provider == 'github':
        github_provider_cfg = get_github_provider_cfg()
        authorization_endpoint = github_provider_cfg["authorization_endpoint"]

        request_uri = requests.Request(
            'GET',
            authorization_endpoint,
            params={
                "client_id": os.getenv("GITHUB_CLIENT_ID"),
                "redirect_uri": os.getenv("GITHUB_REDIRECT_URI"),
                "scope": "user:email",
                "response_type": "code",
                "state": os.urandom(24).hex()
            }
        ).prepare().url

        return jsonify({"url": request_uri})

    elif provider == 'facebook':
        facebook_provider_cfg = get_facebook_provider_cfg()
        authorization_endpoint = facebook_provider_cfg["authorization_endpoint"]

        request_uri = requests.Request(
            'GET',
            authorization_endpoint,
            params={
                "client_id": os.getenv("FACEBOOK_CLIENT_ID"),
                "redirect_uri": os.getenv("FACEBOOK_REDIRECT_URI"),
                "scope": "email",
                "response_type": "code",
                "state": os.urandom(24).hex()
            }
        ).prepare().url

        return jsonify({"url": request_uri})

    return jsonify({"error": "Provider not supported"}), 400

@auth_blueprint.route('/callback/google', methods=['GET'])
def callback_google():
    code = request.args.get('code')
    token = get_google_token(code)
    user_info = get_user_info(token, provider='google')

    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(username=user_info['name'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()

    return jsonify(user_info), 200

@auth_blueprint.route('/callback/github', methods=['GET'])
def callback_github():
    code = request.args.get('code')
    token = get_github_token(code)
    user_info = get_user_info(token, provider='github')

    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(username=user_info['name'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()

    return jsonify(user_info), 200

@auth_blueprint.route('/callback/facebook', methods=['GET'])
def callback_facebook():
    code = request.args.get('code')
    token = get_facebook_token(code)
    user_info = get_user_info(token, provider='facebook')

    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(username=user_info['name'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()

    return jsonify(user_info), 200

@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    if user and user.verify_password(password):
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@auth_blueprint.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "User already exists"}), 400

    new_user = User(email=email, username=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201

