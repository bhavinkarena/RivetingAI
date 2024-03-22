from fastapi import FastAPI
import models
from database import engine
from routers import team, user, document, comment 
import os

models.Base.metadata.create_all(bind=engine)
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware

origins = [
    "*",
    "http://192.168.50.245",
    "http://192.168.50.245:8000",
    "http://127.0.0.1",
    "http://localhost",
    "https://rivetingai.onrender.com/",
    "http://localhost:3000"
]
app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=os.getenv('SESSION_SECRET_KEY'))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(user.app)
app.include_router(team.app)
app.include_router(document.app)
app.include_router(comment.app)