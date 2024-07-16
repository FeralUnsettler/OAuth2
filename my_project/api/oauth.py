
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

