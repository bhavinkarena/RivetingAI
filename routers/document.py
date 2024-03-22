from datetime import datetime
import re
from typing import List
import boto3
from decouple import config
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session as DBSession
from database import SessionLocal
from models import Comment, Document, SharedWith
import schemas
from routers.crud import add_document_to_owner, add_document_to_user, get_document_by_id, get_file_count_by_team_id, get_shared_with_by_document_id_and_user_id, get_user_by_email, get_user_by_id, get_user_by_token, get_users_by_team, team_by_team_name
from email_send import upload_document_mail


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


@app.post("/upload/{team_id}")
async def upload_file(
    team_id: int,
    request: Request,
    file: UploadFile = File(...),
    doc_name: str = Form(...),
    share_with: List[str] = Form(...),
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: DBSession = Depends(get_db),
):
    try:
        print("start")
        print(share_with)
        # Upload file to S3 bucket
        s3_client.upload_fileobj(file.file, config("AWS_BUCKET_NAME"), file.filename)
        # Generate public URL of the uploaded file
        file_url = f"https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{file.filename}"
        print(file_url)
        # file_url = "Dummy"
        # print(file_url)
        # return {"file_url": file_url}
        token = creds.credentials
        user_owner = get_user_by_token(db, token=token)
        # Create document record in the database
        document_record = Document(
            file=file_url,
            team_id=team_id,
            doc_name=doc_name,
            uploaded_by=user_owner.first_name + " " + user_owner.last_name,
        )
        db.add(document_record)
        db.commit()
        shared_with_emails = []
        # Inside your /upload endpoint
        for item in share_with:
            if re.match(r"[^@]+@[^@]+\.[^@]+", item):
                print("Email Found")
                email = item
                user = get_user_by_email(db, email=email)
                if user:
                    add_document_to_user(db, doc_id=document_record.id, user_id=user.id)
                    print(f"Document shared with user '{email}'")
                    shared_with_emails.append(email)
                    print(f"Document shared with user '{email}'")
                else:
                    print(f"User with email '{email}' not found.")
            else:
                first_name = item.split()[0]
                try:
                    last_name = item.split()[1]
                except IndexError:
                    last_name = ""
                all_users = get_users_by_team(db, team_id=team_id)
                for i in all_users:
                    user_of_team = get_user_by_id(db, user_id=i.user_id)
                    if (
                        user_of_team.first_name == first_name
                        and user_of_team.last_name == last_name
                    ):
                        print(user_of_team.email)
                        add_document_to_user(
                            db, doc_id=document_record.id, user_id=user_of_team.id
                        )
                        print("User Found")
                        print(f"Document shared with user '{item}'")
                        shared_with_emails.append(user_of_team.email)
                    # user = get_user_by_username(db, first_name=all_user_of_team.first_name, last_name=all_user_of_team.last_name)
                    # if user:
                    #     add_document_to_user(db, doc_id=document_record.id, user_id=user.id)
                    #     print("User Found")
                    #     print(f"Document shared with user '{item}'")
                team_name = item
                team = team_by_team_name(db, team_name=team_name)
                print(team)
                if team:
                    team_users = get_users_by_team(db, team_id=team.id)
                    print("Team Found")
                    for team_user in team_users:
                        add_document_to_user(
                            db, doc_id=document_record.id, user_id=team_user.user_id
                        )
                        email_demo = get_user_by_id(db, user_id=team_user.user_id)
                        shared_with_emails.append(email_demo.email)
                    print(f"Document shared with team '{team_name}'")
                else:
                    print(f" '{item}' not found.")
        add_document_to_owner(db, doc_id=document_record.id, user_id=user_owner.id)

        print(shared_with_emails)
        for email in shared_with_emails:
            upload_document_mail.send_email(
                email, document_record.id, team.team_name, user_owner.first_name
            )
            print(f"Email sent to {email}")
        return {"message": "Document created and shared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/document/delete/{document_id}")
async def delete_document(document_id: int, db: DBSession = Depends(get_db)):
    try:
        document = get_document_by_id(db, document_id=document_id)

        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        db.delete(document)
        db.commit()

        return {"message": "Document deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/document/{document_id}")
async def get_document(
    request: Request, document_id: int, db: DBSession = Depends(get_db)
):
    try:
        document = get_document_by_id(db, document_id=document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        return document
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/document/approve/{document_id}")
async def approve_shared_with(
     document_id: int,creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()), db: DBSession = Depends(get_db)
):
    try:
        document = get_document_by_id(db, document_id=document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        token = creds.credentials
        user = get_user_by_token(db, token=token)
        shared_with = get_shared_with_by_document_id_and_user_id(
            db, document_id=document_id, user_id=user.id
        )
        if not shared_with:
            raise HTTPException(status_code=404, detail="SharedWith entry not found")
        shared_with.approve = True
        document.approve_count += 1
        db.commit()
        return {"message": "SharedWith entry approved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/document/approve_count/{document_id}")
async def get_approve_count(document_id: int, db: DBSession = Depends(get_db)):
    try:
        # Query the database to get the approve count for the document
        approve_count = (
            db.query(SharedWith)
            .filter(SharedWith.doc_id == document_id, SharedWith.approve == True)
            .count()
        )

        return {"approve_count": approve_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/documents/{document_id}/comments")
async def create_comment(
    comment: schemas.CommentCreate,
    document_id: int,
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: DBSession = Depends(get_db),
):
    document = get_document_by_id(db, document_id=document_id)
    print(document)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    token = creds.credentials
    print("token :-", token)
    user = get_user_by_token(db, token=token)

    comment = Comment(
        text=comment.text,
        user_id=user.id,
        document_id=document_id,
        created_at=datetime.now(),
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@app.put("/document/view/{document_id}")
async def view_document(
    document_id: int,creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()), db: DBSession = Depends(get_db)
):
    try:
        # Check if the document exists
        document = get_document_by_id(db, document_id=document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        # Update the view status for the user
        token = creds.credentials
        user = get_user_by_token(db, token=token)
        shared_with = (
            db.query(SharedWith)
            .filter(SharedWith.doc_id == document_id, SharedWith.user_id == user.id)
            .first()
        )
        if not shared_with:
            raise HTTPException(status_code=404, detail="SharedWith entry not found")

        shared_with.view = True
        document.view_count += 1
        db.commit()

        return {"message": "Document viewed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/document/view_count/{document_id}")
async def get_view_count(document_id: int, db: DBSession = Depends(get_db)):
    try:
        # Get the total view count for the document
        view_count = (
            db.query(SharedWith)
            .filter(SharedWith.doc_id == document_id, SharedWith.view == True)
            .count()
        )

        return {"view_count": view_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/file/count/{team_id}")
async def get_file_count(team_id: int, db: DBSession = Depends(get_db)):
    file_count = get_file_count_by_team_id(db, team_id=team_id)
    if not file_count:
        raise HTTPException(status_code=404, detail="Team not found")
    else:
        return {"message": f"{file_count} files"}
