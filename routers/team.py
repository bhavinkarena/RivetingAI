import re
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from database import SessionLocal
import boto3
from decouple import config
from typing import List
from sqlalchemy.orm import Session as DBSession

from models import Document
from routers.crud import (
    add_document_to_owner,
    add_document_to_user,
    add_owner_to_team,
    add_user_to_team,
    create_team,
    get_team_by_id,
    get_user_by_email,
    get_user_by_token,
)
from utils_file.apiError import ApiError
from utils_file.apiResponse import ApiResponse
from email_send import join_team_mail


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = APIRouter()

s3_client = boto3.client(
    "s3",
    aws_access_key_id=config("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=config("AWS_SECRET_ACCESS_KEY"),
)
AWS_BUCKET_NAME = config("AWS_BUCKET_NAME")


@app.post("/create_team")
def create_team_api(
    file: UploadFile = File(...),
    user_email: List[str] = Form(...),
    team: str = Form(...),
    doc_name: str = Form(...),
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: DBSession = Depends(get_db),
):
    try:
        print("start")
        # Create the team
        team_db = create_team(db, team_name=team)

        # Get the user who is creating the team
        token = creds.credentials
        user_owner = get_user_by_token(db, token=token)

        # Add the user who created the team as the team owner
        add_owner_to_team(db, team_id=team_db.id, user_id=user_owner.id)

        # Upload the document if a file is provided
        if file:
            # Upload file to S3 bucket
            s3_client.upload_fileobj(
                file.file, config("AWS_BUCKET_NAME"), file.filename
            )
            # Generate public URL of the uploaded file
            file_url = f"https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{file.filename}"

            # Create document record in the database with the team ID
            document_record = Document(
                file=file_url,
                team_id=team_db.id,
                doc_name=doc_name,  # You can change this to the actual document name
                uploaded_by=user_owner.first_name + " " + user_owner.last_name,
            )
            db.add(document_record)
            db.commit()
            doc_id = document_record.id
            for i in user_email:
                user = get_user_by_email(db, email=i)
                if user:
                    add_document_to_user(db, doc_id=doc_id, user_id=user.id)

            add_document_to_owner(db, doc_id=doc_id, user_id=user_owner.id)

        # Send invitation emails to team members
        for email in user_email:
            print(email)
            join_team_mail.send_email(
                email, team_db.team_token, team_db.team_name, user_owner.first_name,
                user_owner.first_name + " " +user_owner.last_name
            )
            user = get_user_by_email(db, email=email)
            if user:
                add_user_to_team(db, team_id=team_db.id, user_id=user.id)

        return ApiResponse(
            statusCode=200,
            data={
                "file": document_record.file,
                "team_id": team_db.id,
                "doc_name": document_record.doc_name,
                "uploaded_by": document_record.uploaded_by
            },
            message="Team created successfully",
        ).__dict__
    except Exception as e:
        return ApiError(
            statusCode=500,
            message=str(e),
        ).__dict__


@app.post("/invite/{team_id}")
async def invite_team_members(
    team_id: int,
    user_email: List[str] = Form(...),
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: DBSession = Depends(get_db),
):
    try:
        team_id = team_id
        emails = user_email
        team_db = get_team_by_id(db, team_id=team_id)

        token = creds.credentials
        user_owner = get_user_by_token(db, token=token)
        print(user_owner.first_name)
        for email in emails:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email):
                user = get_user_by_email(db, email=email)
                if user:
                    add_user_to_team(db, team_id=team_id, user_id=user.id)
                    # Send invitation email to the user
                    join_team_mail.send_email(
                        email,
                        team_db.team_token,
                        team_db.team_name,
                        user_owner.first_name,
                        user_owner.first_name +" " +user_owner.last_name
                    )
                    print(f"Invitation sent to {email}")
                else:
                    print(f"User with email '{email}' not found.")
            else:
                print(f"Invalid email format: {email}")
        return ApiResponse(
            statusCode=200,
            data={},
            message="Invitation sent successfully",
        ).__dict__
    except Exception as e:
        return ApiError(
            statusCode=500,
            message=str(e),
        ).__dict__