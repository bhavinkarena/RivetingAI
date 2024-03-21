import re
from fastapi import FastAPI, Depends, Form, HTTPException,File, Query, Request, UploadFile, Response
from fastapi.responses import HTMLResponse
from httpx import HTTPError
from sqlalchemy.orm import Session as DBSession
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import boto3
from typing import List
from decouple import config
from crud import (
    add_document_to_owner,
    add_document_to_user,
    add_owner_to_team,
    add_user_to_team,
    create_access_token,
    create_team,
    get_comment_by_id,
    get_comment_count_by_document_id,
    get_comments_by_document_id,
    get_document_by_id,
    get_file_count_by_team_id,
    get_shared_with_by_document_id_and_user_id,
    get_team_by_id,
    get_teamUser_by_team_user,
    get_user_by_email,
    get_user_by_google_id,
    get_user_by_id,
    get_user_by_microsoft_id,
    get_user_by_token,
    get_users_by_team,
    team_by_team_name,
    team_by_team_token,
)
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse
import join_team_mail
import upload_document_mail
from database import engine, SessionLocal
from models import Base, Document, SharedWith, User, Comment
import schemas
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import requests


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base.metadata.create_all(bind=engine)
app = FastAPI()

origins = [
    "*",
    "http://192.168.50.245",
    "http://192.168.50.245:8000",
    "http://127.0.0.1",
    "http://localhost",
    "https://rivetingai.onrender.com/",
    "http://localhost:3000"
]


app.add_middleware(SessionMiddleware, secret_key=os.getenv('SESSION_SECRET_KEY'))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/", response_class=HTMLResponse)
async def root():
    return "<html><h1>This is the endpoint for RivetingAI's API. Please visit <a id='link'>This Link</a> for useful documentation.</h1><script>document.getElementById('link').href = window.location.href + 'docs'</script></html>"

@app.post("/register")
def register_user(
        request: Request, response: Response, user: schemas.UserCreate, team_token: str = None, db: DBSession = Depends(get_db)
):
    try:
        password = pwd_context.hash(user.password)
        emailexists = get_user_by_email(db, email=user.email)
        if emailexists:
            raise HTTPException(
                status_code=400, detail="This email is already registered."
            )

        else:
            db_user = User(
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                password=password,
            )
            db.add(db_user)
            access_token_expires = timedelta(
                minutes=int(config("ACCESS_TOKEN_EXPIRE_MINUTES"))
            )
            access_token = create_access_token(
                data={"sub": db_user.email}, expires_delta=access_token_expires
            )
            db_user.security_token = access_token
        db.commit()
        if team_token:
            team = team_by_team_token(db, team_token=team_token)
            user = get_user_by_email(db, email=db_user.email)
            add_user_to_team(db, team_id=team.id, user_id=user.id)
            team_user = get_teamUser_by_team_user(db, team=team.id, user=user.id)
            team_user.is_accept = True
        db.commit()
        response.set_cookie(key="token", value=access_token)
        if request.cookies.get("token") is None:
            raise HTTPException(status_code=400, detail="Cookie is not set")
        return {"message": "User created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=e)

@app.post("/login")
def login_user(
    user: schemas.UserLogin,
    request: Request,
    response: Response,
    team_token: str = None,
    db: DBSession = Depends(get_db),
):
    try:
        db_user = get_user_by_email(db, email=user.email)
        if not db_user or not pwd_context.verify(user.password, db_user.password):
            raise HTTPException(status_code=400, detail="Invalid credentials")
        access_token_expires = timedelta(
            minutes=int(config("ACCESS_TOKEN_EXPIRE_MINUTES"))
        )
        access_token = create_access_token(
            data={"sub": db_user.email}, expires_delta=access_token_expires
        )
        db_user.security_token = access_token
        if team_token:
            team = team_by_team_token(db, team_token=team_token)
            print(team.id)
            user = get_user_by_email(db, email=db_user.email)
            print(user.id)
            team_user = get_teamUser_by_team_user(db, team=team.id, user=user.id)
            print(team_user)
            team_user.is_accept = True
        db.commit()
        response.set_cookie(key="token", value=access_token)
        print("-----------coockie token--------", request.cookies.get("token"))
        if request.cookies.get("token") == None:
            raise HTTPException(status_code=400, detail="Cookie is not set")
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/logout")
def logout_user(response: Response):
    response.delete_cookie(key="token")
    return {"message": "Logout successful"}

s3_client = boto3.client(
    "s3",
    aws_access_key_id=config("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=config("AWS_SECRET_ACCESS_KEY")
)
AWS_BUCKET_NAME=config("AWS_BUCKET_NAME")
    
@app.post("/create_team")
def create_team_api(
    request: Request,
    file: UploadFile = File(...),
    user_email: List[str] = Form(...),
    team:  str = Form(...),
    version_number: str = Form(...),
    doc_name: str = Form(...),
    db: DBSession = Depends(get_db)
):
    try:
        print("start")
        # Create the team
        team_db = create_team(db, team_name=team)
        
        # Get the user who is creating the team
        token = request.cookies.get("token")
        user_owner = get_user_by_token(db, token=token)
        print("token:-",token)
        # Add the user who created the team as the team owner
        add_owner_to_team(db, team_id=team_db.id, user_id=user_owner.id)
        
        # Upload the document if a file is provided
        if file:
            # Upload file to S3 bucket
            s3_client.upload_fileobj(file.file, config("AWS_BUCKET_NAME"), file.filename)
            # Generate public URL of the uploaded file
            file_url = f"https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{file.filename}"
            
            # Create document record in the database with the team ID
            document_record = Document(
                file=file_url,
                team_id=team_db.id,
                doc_name=doc_name,  # You can change this to the actual document name
                version_number=version_number,  # You can change this to the actual version number
                uploaded_by=user_owner.first_name + " " + user_owner.last_name,
            )
            db.add(document_record)
            db.commit()
            doc_id = document_record.id
            for i in user_email:
                user = get_user_by_email(db, email=i)
                if user:
                    add_document_to_user(db, doc_id=doc_id,user_id=user.id )
            
            add_document_to_owner(db, doc_id=doc_id,user_id=user_owner.id )
            
        
        # Send invitation emails to team members
        for email in user_email:
            join_team_mail.send_email(email, team_db.team_token,team_db.team_name,user_owner.first_name)
            user = get_user_by_email(db, email=email)
            if user:
                add_user_to_team(db, team_id=team_db.id, user_id=user.id)
        
        return {"message": f"Team {team_db.team_name} created successfully "}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload/{team_id}")
async def upload_file(
    team_id: int,
    request: Request,
    file: UploadFile = File(...),
    doc_name: str = Form(...),
    share_with: List[str] = Form(...),
    version_number: str = Form(...),
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
        token = request.cookies.get("token")
        user_owner = get_user_by_token(db, token=token)
        # Create document record in the database
        document_record = Document(
            file=file_url,
            team_id=team_id,
            doc_name=doc_name,
            version_number=version_number,
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
            upload_document_mail.send_email(email, document_record.id,team.team_name,user_owner.first_name)
            print(f"Email sent to {email}")
        return {"message": "Document created and shared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))   

@app.post("/invite/{team_id}")
async def invite_team_members(request:Request,team_id:int, user_email: List[str] = Form(...), db: DBSession = Depends(get_db)):
    try:
        team_id = team_id
        emails = user_email
        team_db = get_team_by_id(db, team_id=team_id)

        token = request.cookies.get("token")
        user_owner = get_user_by_token(db, token=token)
        print(user_owner.first_name)    
        for email in emails:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email):
                user = get_user_by_email(db, email=email)
                if user:
                    add_user_to_team(db, team_id=team_id, user_id=user.id)
                    # Send invitation email to the user
                    join_team_mail.send_email(email, team_db.team_token,team_db.team_name,user_owner.first_name)
                    print(f"Invitation sent to {email}")
                else:
                    print(f"User with email '{email}' not found.")
            else:
                print(f"Invalid email format: {email}")
        return {"message": "Invitations sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/document/delete/{document_id}")
async def delete_document(
    document_id: int,
    db: DBSession = Depends(get_db)
):
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
    request: Request,
    document_id: int,
    db: DBSession = Depends(get_db)
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
    request: Request,
    document_id: int,
    db: DBSession = Depends(get_db)
):
    try:
        document = get_document_by_id(db, document_id=document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        token = request.cookies.get("token")
        user = get_user_by_token(db, token=token)
        shared_with = get_shared_with_by_document_id_and_user_id(db, document_id=document_id, user_id=user.id)
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
        approve_count = db.query(SharedWith).filter(
            SharedWith.doc_id == document_id,
            SharedWith.approve == True
        ).count()

        return {"approve_count": approve_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
    scopes={"profile":"profile", "email":"email"}
)

# Your Google OAuth 2.0 credentials
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = config("GOOGLE_REDIRECT_URI")

@app.get("/login/google/")
async def login_with_google():
    redirect_uri = f"{GOOGLE_REDIRECT_URI}"
    print(redirect_uri)
    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&scope=openid%20profile%20email")

@app.get("/login/google/callback")
async def google_callback(
    code: str,
    request: Request,
    response1: Response,
    team_token: str = None,
    db: DBSession = Depends(get_db),
):
    try:
        token_url = "https://oauth2.googleapis.com/token"
        payload = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        print(payload)
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        profile_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_response = requests.get(profile_url, headers=headers)
        profile_response.raise_for_status()
        profile_data = profile_response.json()
        user = get_user_by_google_id(db, google_id=profile_data["id"])
        emailexists = get_user_by_email(db, email=profile_data["email"])
        if emailexists:
            emailexists.google_id = profile_data["id"]
            emailexists.profile_image = profile_data.get("picture")
        else:
            if not user:
                # User does not exist, create a new user
                user = User(
                    google_id=profile_data["id"],
                    email=profile_data["email"],
                    first_name=profile_data.get("given_name"),
                    last_name=profile_data.get("family_name"),
                    profile_image=profile_data.get("picture"),
                )
                db.add(user)
        if user==None:
            user = emailexists
        # Generate an access token for the user
        access_token_expires = timedelta(
            minutes=int(config("ACCESS_TOKEN_EXPIRE_MINUTES"))
        )
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        user.security_token = access_token
        if team_token:
            team = team_by_team_token(db, team_token=team_token)
            print(team.id)
            user = get_user_by_email(db, email=user.email)
            print(user.id)
            team_user = get_teamUser_by_team_user(db, team=team.id, user=user.id)
            print(team_user)
            team_user.is_accept = True
        db.commit()
        response1.set_cookie(key="token", value=access_token)
        # return {"access_token": access_token, "token_type": "bearer"}
        return RedirectResponse(url=f"http://localhost:3000/mydocuments")
    except HTTPError as e:
        raise HTTPException(status_code=400, detail=f"HTTP error occurred: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")
    
# for microsoft login
MICROSOFT_REDIRECT_URI=config("MICROSOFT_REDIRECT_URI")
MICROSOFT_CLIENT_ID=config("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET=config("MICROSOFT_CLIENT_SECRET")

@app.get("/login/microsoft")
async def login_with_microsoft():
    redirect_uri = f"{MICROSOFT_REDIRECT_URI}"
    return RedirectResponse(url=f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id={MICROSOFT_CLIENT_ID}&redirect_uri={redirect_uri}&scope=User.Read")

@app.get("/login/microsoft/callback")
async def login_with_microsoft_callback(
    request: Request,
    code: str,
    response1: Response,
    team_token: str = None,
    db: DBSession = Depends(get_db),
):
    try:
        print(code)
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        payload = {
            "code": code,
            "client_id": MICROSOFT_CLIENT_ID,
            "client_secret": MICROSOFT_CLIENT_SECRET,
            "redirect_uri": MICROSOFT_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        response = requests.post(token_url, data=payload)
        print(response)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        profile_url = "https://graph.microsoft.com/v1.0/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_response = requests.get(profile_url, headers=headers)
        profile_response.raise_for_status()
        profile_data = profile_response.json()
        print(profile_data)
        user = get_user_by_microsoft_id(db, microsoft_id=profile_data["id"])
        emailexists = get_user_by_email(db,email=profile_data.get("email") or profile_data.get("mail") or profile_data.get("userPrincipalName"))
        print(emailexists)
        if emailexists:
            emailexists.microsoft_id = profile_data["id"]
            emailexists.profile_image = None
        else:
            if not user:
                # User does not exist, create a new user
                user = User(
                    microsoft_id=profile_data["id"],
                    email=profile_data.get("email") or profile_data.get("mail") or profile_data.get("userPrincipalName"),
                    first_name=profile_data.get("givenName"),
                    last_name=profile_data.get("surname"),
                    profile_image=None,
                )
                db.add(user)
        if user==None:
            user = emailexists
        # Generate an access token for the user
        access_token_expires = timedelta(
            minutes=int(config("ACCESS_TOKEN_EXPIRE_MINUTES"))
        )
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        user.security_token = access_token
        if team_token:
            team = team_by_team_token(db, team_token=team_token)
            print(team.id)
            user = get_user_by_email(db, email=user.email)
            print(user.id)
            team_user = get_teamUser_by_team_user(db, team=team.id, user=user.id)
            print(team_user)
            team_user.is_accept = True
        db.commit()
        response1.set_cookie(key="token", value=access_token)
        return RedirectResponse(url=f"http://localhost:3000/mydocuments")
    except HTTPError as e:
        raise HTTPException(status_code=400, detail=f"HTTP error occurred: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")
    
@app.post("/documents/{document_id}/comments")
async def create_comment(
    comment: schemas.CommentCreate,
    document_id: int,
    request: Request,
    db: DBSession = Depends(get_db)
):
    document = get_document_by_id(db, document_id=document_id)
    print(document)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    token = request.cookies.get("token")
    print("token :-", token)
    user = get_user_by_token(db, token=token)

    comment = Comment(
        text=comment.text,
        user_id=user.id,
        document_id=document_id,
        created_at=datetime.now()
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment
    
@app.post("/comments/{comment_id}/replies")
async def create_reply(
    comment: schemas.CommentCreate,
    comment_id: int,
    request: Request,
    db: DBSession = Depends(get_db)
):
    # Check if the parent comment exists
    parent_comment = get_comment_by_id(db, comment_id = comment_id)
    if not parent_comment:
        raise HTTPException(status_code=404, detail="Parent comment not found")
    
    token = request.cookies.get("token")
    print("token :-", token)
    user = get_user_by_token(db, token=token)

    # Create the reply comment
    reply_comment = Comment(
        text=comment.text,
        user_id=user.id,  # Assuming 'user' is available in the current context
        document_id=parent_comment.document_id,
        parent_comment_id=comment_id,
        created_at=datetime.now()
    )
    db.add(reply_comment)
    db.commit()
    db.refresh(reply_comment)

    return {"message": "Reply created successfully"}

@app.get("/documents/{document_id}/comments")
async def get_comments_for_document(
    document_id: int,
    db: DBSession = Depends(get_db)
):
    comments = get_comments_by_document_id(db, document_id=document_id)
    return comments

@app.delete("/comments/delete/{comment_id}")
async def delete_comment(
    comment_id: int,
    db: DBSession = Depends(get_db)
):
    # Check if the comment exists
    comment = get_comment_by_id(db, comment_id = comment_id) 
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Delete the comment and its replies recursively
    def delete_comment_recursive(comment_id):
        comment = get_comment_by_id(db, comment_id = comment_id) 
        if not comment:
            return
        
        replies = db.query(Comment).filter(Comment.parent_comment_id == comment_id).all()
        print(replies)
        for reply in replies:
            delete_comment_recursive(reply.id)
        db.delete(comment)
        db.commit()
    delete_comment_recursive(comment_id)

    return {"message": "Comment and replies deleted successfully"}

@app.put("/comments/{comment_id}/edit")
async def edit_comment(
    comment_id: int,
    edited_comment: schemas.CommentCreate,
    request: Request,
    db: DBSession = Depends(get_db)
):
    # Get the comment from the database
    comment = get_comment_by_id(db, comment_id=comment_id)
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Check if the user is authenticated and get their user ID
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = get_user_by_token(db, token=token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Check if the user is the author of the comment
    if comment.user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own comments")

    # Update the comment text
    comment.text = edited_comment.text
    db.commit()
    return {"message": "Comment updated successfully"}

@app.post("/comments/count/{document_id}")
async def get_comment_count(document_id: int, db: DBSession = Depends(get_db)):
    comment_count = get_comment_count_by_document_id(db, document_id=document_id)
    if not comment_count:
        raise HTTPException(status_code=404, detail="Document not found")
    else:
        return {"message": f"{comment_count} comments"}
    
@app.put("/document/view/{document_id}")
async def view_document(request:Request,document_id: int, db: DBSession = Depends(get_db)):
    try:
        # Check if the document exists
        document = get_document_by_id(db, document_id=document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        # Update the view status for the user
        token = request.cookies.get("token")
        user = get_user_by_token(db, token=token)
        shared_with = db.query(SharedWith).filter(
            SharedWith.doc_id == document_id,
            SharedWith.user_id == user.id
        ).first()
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
        view_count = db.query(SharedWith).filter(
            SharedWith.doc_id == document_id,
            SharedWith.view == True
        ).count()

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
    
    