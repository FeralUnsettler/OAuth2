
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

