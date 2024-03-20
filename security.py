from fastapi import Depends
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# import classes

origins = [
    "*",
    "http://192.168.50.245",
    "http://192.168.50.245:8000",
    "http://127.0.0.1",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000"
]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
