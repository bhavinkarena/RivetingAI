from datetime import datetime, timedelta , timezone
import uuid
from decouple import config
from fastapi import Form
from jose import jwt
from requests import Session
from models import Document, SharedWith, Team, TeamUser, User, Comment

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config('SECRET_KEY'), algorithm=config('ALGORITHM'))
    return encoded_jwt

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_user_by_token(db: Session, token: str):
    return db.query(User).filter(User.security_token == token).first()

def create_team(db: Session, team_name: str):
    team_token = str(uuid.uuid4())
    print(team_token)
    team = Team(team_name=team_name,team_token=team_token)
    db.add(team)
    db.commit()
    db.refresh(team)
    return team

def add_user_to_team(db: Session, team_id: int, user_id: int):
    team_user = TeamUser(team_id=team_id, user_id=user_id)
    db.add(team_user)
    db.commit()
    db.refresh(team_user)
    return team_user

def add_owner_to_team(db: Session, team_id: int, user_id: int):
    team_user = TeamUser(team_id=team_id, user_id=user_id)
    team_user.is_accept = True
    db.add(team_user)
    db.commit()
    db.refresh(team_user)
    return team_user

def add_document_to_user(db: Session, doc_id: int, user_id: int):
    """
    Add a document to a user in the shared_with table.
    """
    shared_with_entry = SharedWith(doc_id=doc_id, user_id=user_id)
    db.add(shared_with_entry)
    db.commit()
    return shared_with_entry

def add_document_to_owner(db: Session, doc_id: int, user_id: int):
    """
    Add a document to a user in the shared_with table.
    """
    shared_with_entry = SharedWith(doc_id=doc_id, user_id=user_id)
    shared_with_entry.approve=True
    db.add(shared_with_entry)
    db.commit()
    return shared_with_entry

def team_by_team_token(db: Session, team_token: str):
    return db.query(Team).filter(Team.team_token == team_token).first()

def get_team_by_id(db: Session, team_id: int):
    return db.query(Team).filter(Team.id == team_id).first()

def get_user_by_google_id(db: Session, google_id: str):
    return db.query(User).filter(User.google_id == google_id).first()

def get_user_by_microsoft_id(db: Session, microsoft_id: str):
    return db.query(User).filter(User.microsoft_id == microsoft_id).first()

def get_teamUser_by_team_user(db: Session, team: int, user: int):
    return db.query(TeamUser).filter(TeamUser.team_id == team,TeamUser.user_id==user).first()

def get_document_by_id(db: Session, document_id: int):
    print(document_id)
    return db.query(Document).filter(Document.id == document_id).first()

def get_comment_by_id(db: Session, comment_id: int):
    print(comment_id)
    return db.query(Comment).filter(Comment.id == comment_id).first()

def get_comments_by_document_id(db: Session, document_id: int):
    print(document_id)
    return db.query(Comment).filter(Comment.document_id == document_id).all()

def get_replies_by_comment_id(db: Session, comment_id: int):
    print(comment_id)
    return db.query(Comment).filter(Comment.parent_comment_id == comment_id).all()

def team_by_team_name(db: Session, team_name: str):
    """
    Get a team by its name.
    """
    return db.query(Team).filter(Team.team_name == team_name).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_users_by_team(db: Session, team_id: int):
    """
    Get all users belonging to a specific team.
    """
    return db.query(TeamUser).filter(TeamUser.team_id == team_id).all()

def get_shared_with_by_document_id_and_user_id(db: Session, document_id: int,user_id: int):
    """
    Get all users who have shared a document.
    """
    return db.query(SharedWith).filter_by(doc_id=document_id, user_id=user_id).first()

def get_comment_count_by_document_id(db: Session, document_id: int):
    return db.query(Comment).filter_by(document_id=document_id).count()

def get_file_count_by_team_id(db: Session, team_id: int):
    return db.query(Document).filter_by(team_id=team_id).count()





