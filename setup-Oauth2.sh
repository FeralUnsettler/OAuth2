#!/bin/bash

# Variáveis de ambiente
cat <<EOF > .env
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_DB=mydatabase

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/callback/google

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:5000/auth/callback/github

FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
FACEBOOK_REDIRECT_URI=http://localhost:5000/auth/callback/facebook
EOF

# Estrutura de diretórios
mkdir -p my_project/{api,client,frontend}
cd my_project

# Arquivo Docker Compose
cat <<EOF > docker-compose.yml
version: '3.8'

services:
  db:
    image: postgres:latest
    environment:
      POSTGRES_USER: \${POSTGRES_USER}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_DB: \${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network

  api:
    build: ./api
    volumes:
      - ./api:/app
    environment:
      - GOOGLE_CLIENT_ID=\${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=\${GOOGLE_CLIENT_SECRET}
      - GOOGLE_REDIRECT_URI=\${GOOGLE_REDIRECT_URI}
      - GITHUB_CLIENT_ID=\${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=\${GITHUB_CLIENT_SECRET}
      - GITHUB_REDIRECT_URI=\${GITHUB_REDIRECT_URI}
      - FACEBOOK_CLIENT_ID=\${FACEBOOK_CLIENT_ID}
      - FACEBOOK_CLIENT_SECRET=\${FACEBOOK_CLIENT_SECRET}
      - FACEBOOK_REDIRECT_URI=\${FACEBOOK_REDIRECT_URI}
      - DATABASE_URL=postgresql+psycopg2://\${POSTGRES_USER}:\${POSTGRES_PASSWORD}@db:5432/\${POSTGRES_DB}
    networks:
      - app-network
    depends_on:
      - db

  client:
    build: ./client
    volumes:
      - ./client:/app
    networks:
      - app-network
    depends_on:
      - api

  frontend:
    build: ./frontend
    volumes:
      - ./frontend:/app
    networks:
      - app-network
    depends_on:
      - api

networks:
  app-network:
    driver: bridge

volumes:
  postgres_data:
EOF

# Dockerfile para a API
cat <<EOF > api/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["flask", "run", "--host=0.0.0.0"]
EOF

# Dockerfile para o Cliente FastAPI
cat <<EOF > client/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# Dockerfile para o Frontend Flask
cat <<EOF > frontend/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["flask", "run", "--host=0.0.0.0", "--port=5001"]
EOF

# Requirements para a API
cat <<EOF > api/requirements.txt
Flask
Flask-SQLAlchemy
psycopg2-binary
requests
python-dotenv
EOF

# Requirements para o Cliente FastAPI
cat <<EOF > client/requirements.txt
fastapi
httpx
EOF

# Requirements para o Frontend Flask
cat <<EOF > frontend/requirements.txt
Flask
EOF

# Código da API
cat <<EOF > api/app.py
from flask import Flask
from routes import auth_blueprint
from models import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:password@db:5432/mydatabase'
db.init_app(app)

app.register_blueprint(auth_blueprint, url_prefix='/auth')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
EOF

cat <<EOF > api/models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
EOF

cat <<EOF > api/routes.py
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

EOF

cat <<EOF > api/oauth.py

import requests
import json
import os

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
GITHUB_DISCOVERY_URL = "https://api.github.com"
FACEBOOK_DISCOVERY_URL = "https://graph.facebook.com/v10.0"

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def get_google_token(code):
    token_response = requests.post(
        get_google_provider_cfg()["token_endpoint"],
        data={
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),
        }
    )
    return token_response.json()

def get_github_provider_cfg():
    return {"authorization_endpoint": "https://github.com/login/oauth/authorize", "token_endpoint": "https://github.com/login/oauth/access_token"}

def get_github_token(code):
    token_response = requests.post(
        get_github_provider_cfg()["token_endpoint"],
        data={
            "client_id": os.getenv("GITHUB_CLIENT_ID"),
            "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": os.getenv("GITHUB_REDIRECT_URI"),
        },
        headers={"Accept": "application/json"}
    )
    return token_response.json()

def get_facebook_provider_cfg():
    return {"authorization_endpoint": "https://www.facebook.com/v10.0/dialog/oauth", "token_endpoint": "https://graph.facebook.com/v10.0/oauth/access_token"}

def get_facebook_token(code):
    token_response = requests.get(
        get_facebook_provider_cfg()["token_endpoint"],
        params={
            "client_id": os.getenv("FACEBOOK_CLIENT_ID"),
            "client_secret": os.getenv("FACEBOOK_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": os.getenv("FACEBOOK_REDIRECT_URI"),
        }
    )
    return token_response.json()

def get_user_info(token, provider):
    if provider == "google":
        userinfo_endpoint = get_google_provider_cfg()["userinfo_endpoint"]
        response = requests.get(userinfo_endpoint, headers={"Authorization": f"Bearer {token['access_token']}"})
    elif provider == "github":
        response = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {token['access_token']}"})
    elif provider == "facebook":
        response = requests.get("https://graph.facebook.com/me?fields=id,name,email", headers={"Authorization": f"Bearer {token['access_token']}"})
    return response.json()

EOF


cat <<EOF > client/main.py

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import requests
import os

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    email: str

class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    response = requests.post("http://localhost:5000/auth/login", json={"email": form_data.username, "password": form_data.password})
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    return {"access_token": response.json().get("token"), "token_type": "bearer"}

@app.post("/auth/{provider}")
async def auth(provider: str):
    response = requests.get(f"http://localhost:5000/auth/login/{provider}")
    return response.json()

@app.get("/auth/callback/{provider}")
async def auth_callback(provider: str, code: str):
    response = requests.get(f"http://localhost:5000/auth/callback/{provider}?code={code}")
    return response.json()

@app.post("/auth/signup")
async def signup(user: User):
    response = requests.post("http://localhost:5000/auth/signup", json=user.dict())
    return response.json()

EOF


cat <<EOF > frontend/app.py

from flask import Flask, render_template, redirect, url_for, request, jsonify
import requests
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login/<provider>')
def login(provider):
    response = requests.get(f"http://localhost:5000/auth/login/{provider}")
    return redirect(response.json()['url'])

@app.route('/auth/callback/<provider>')
def callback(provider):
    code = request.args.get('code')
    response = requests.get(f"http://localhost:5000/auth/callback/{provider}?code={code}")
    return jsonify(response.json())

@app.route('/auth/login', methods=['POST'])
def auth_login():
    email = request.form.get('email')
    password = request.form.get('password')
    response = requests.post("http://localhost:5000/auth/login", json={"email": email, "password": password})
    return jsonify(response.json())

@app.route('/auth/signup', methods=['POST'])
def auth_signup():
    email = request.form.get('email')
    password = request.form.get('password')
    response = requests.post("http://localhost:5000/auth/signup", json={"email": email, "password": password})
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)


EOF




cat <<EOF > frontend/app.py

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="{{ url_for('static', filename='css/styles.css') }}">
</head>
<body>
    <div class="container">
        {% block content %}
        {% endblock %}
    </div>
</body>
</html>

EOF

#Comentando o que funciona

cat <<EOF > frontend/templates/login.html

{% extends "base.html" %}

{% block content %}
<h2>Login</h2>
<form action="{{ url_for('auth_login') }}" method="POST">
    <label for="email">Email:</label>
    <input type="email" id="email" name="email">
    <label for="password">Password:</label>
    <input type="password" id="password" name="password">
    <button type="submit">Login</button>
</form>
<div>
    <a href="{{ url_for('login', provider='google') }}">Login with Google</a>
    <a href="{{ url_for('login', provider='github') }}">Login with GitHub</a>
    <a href="{{ url_for('login', provider='facebook') }}">Login with Facebook</a>
</div>
{% endblock %}


EOF


#Comentando o que funciona

cat <<EOF > frontend/static/css/styles.css


body {
    font-family: Arial, sans-serif;
    background-color: #f4f4f4;
    margin: 0;
    padding: 0;
}

.container {
    max-width: 600px;
    margin: 50px auto;
    padding: 20px;
    background-color: #fff;
    border-radius: 8px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

h2 {
    text-align: center;
}

form {
    display: flex;
    flex-direction: column;
}

label {
    margin-bottom: 5px;
}

input {
    margin-bottom: 15px;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 4px;
}

button {
    padding: 10px;
    background-color: #007bff;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

button:hover {
    background-color: #0056b3;
}

div a {
    display: block;
    margin-top: 10px;
    text-align: center;
    color: #007bff;
}

div a:hover {
    text-decoration: underline;
}

EOF

