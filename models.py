from sqlalchemy import ARRAY, Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from sqlalchemy.orm import relationship
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    profile_image = Column(String)
    google_id = Column(String, unique=True)
    microsoft_id = Column(String, unique=True)
    security_token = Column(String)
    created_at = Column(DateTime, default=datetime.now)

    teams = relationship("Team", secondary="team_users", back_populates="users")
    comments = relationship("Comment", back_populates="user")

class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    team_name = Column(String, unique=True, index=True)
    latest_activity_time = Column(DateTime)
    team_token = Column(String)

    users = relationship("User", secondary="team_users", back_populates="teams")
    
class TeamUser(Base):
    __tablename__ = "team_users"
    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    is_accept    = Column(Boolean, default=False)

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"))
    file = Column(String)
    doc_name = Column(String, index=True)
    version_number = Column(String)
    uploaded_by = Column(String)
    approve_count = Column(Integer, default=1)
    view_count = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=datetime.now)

    comments = relationship("Comment", back_populates="document")


class SharedWith(Base):
    __tablename__ = "shared_with"
    id = Column(Integer, primary_key=True, index=True)
    doc_id = Column(Integer, ForeignKey("documents.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    approve = Column(Boolean, default=False)
    view = Column(Boolean, default=False)

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    document_id = Column(Integer, ForeignKey("documents.id"))
    parent_comment_id = Column(Integer, ForeignKey("comments.id"))
    created_at = Column(DateTime, default=datetime.now)

    user = relationship("User", back_populates="comments")
    document = relationship("Document", back_populates="comments")
    replies = relationship("Comment", foreign_keys=[parent_comment_id])

# Assuming User model already exists with a 'comments' relationship
