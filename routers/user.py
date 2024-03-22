from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2AuthorizationCodeBearer
from httpx import HTTPError
import requests
from database import engine, SessionLocal
from models import Base, User
from passlib.context import CryptContext
from decouple import config
from sqlalchemy.orm import Session as DBSession
from routers.crud import add_user_to_team, create_access_token, get_teamUser_by_team_user, get_user_by_email, get_user_by_google_id, get_user_by_microsoft_id, get_user_by_token, team_by_team_token
import schemas


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base.metadata.create_all(bind=engine)

app = APIRouter()

@app.post("/register")
def register_user(

        response: Response,user: schemas.UserCreate, team_token: str = None, db: DBSession = Depends(get_db)
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
            print(team.id)
            user = get_user_by_email(db, email=db_user.email)
            print(user.id)
            add_user_to_team(db, team_id=team.id, user_id=user.id)
            team_user = get_teamUser_by_team_user(db, team=team.id, user=user.id)
            print(team_user)
            team_user.is_accept = True
        db.commit()
        
        response.set_cookie(key="token", value=access_token, httponly=True)
        return {"message": "User created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

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
        response.set_cookie(key="token", value=access_token, httponly=True)
    
        print("-----------coockie token--------", request.cookies.get("token"))
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.get("/logout")
def logout_user(response: Response):
    response.delete_cookie(key="token")
    return {"message": "Logout successful"}


@app.get("/current_user/name")
def read_current_user(
    
    db: DBSession = Depends(get_db),
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer())
):
    token = creds.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = get_user_by_token(db, token=token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"firstname": user.first_name, "lastname": user.last_name,"email": user.email}

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
    scopes={"profile": "profile", "email": "email"},
)

# Your Google OAuth 2.0 credentials
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = config("GOOGLE_REDIRECT_URI")

@app.get("/login/google/")
async def login_with_google():
    redirect_uri = f"{GOOGLE_REDIRECT_URI}"
    print(redirect_uri)
    return RedirectResponse(
        url=f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={redirect_uri}&scope=openid%20profile%20email"
    )


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
        if user == None:
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
        response1.set_cookie(key="token", value=access_token, httponly=True)
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPError as e:
        raise HTTPException(status_code=400, detail=f"HTTP error occurred: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")


# for microsoft login
MICROSOFT_REDIRECT_URI = config("MICROSOFT_REDIRECT_URI")
MICROSOFT_CLIENT_ID = config("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = config("MICROSOFT_CLIENT_SECRET")


@app.get("/login/microsoft")
async def login_with_microsoft():
    redirect_uri = f"{MICROSOFT_REDIRECT_URI}"
    return RedirectResponse(
        url=f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id={MICROSOFT_CLIENT_ID}&redirect_uri={redirect_uri}&scope=User.Read"
    )


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

        emailexists = get_user_by_email(
            db,
            email=profile_data.get("email")
            or profile_data.get("mail")
            or profile_data.get("userPrincipalName"),
        )

        if emailexists:
            emailexists.microsoft_id = profile_data["id"]
            emailexists.profile_image = None
        else:
            if not user:
                # User does not exist, create a new user
                user = User(
                    microsoft_id=profile_data["id"],
                    email=profile_data.get("email")
                    or profile_data.get("mail")
                    or profile_data.get("userPrincipalName"),
                    first_name=profile_data.get("givenName"),
                    last_name=profile_data.get("surname"),
                    profile_image=None,
                )
                db.add(user)
        # Generate an access token for the user
        if user == None:
            user = emailexists
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
        response1.set_cookie(key="token", value=access_token, httponly=True)
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPError as e:
        raise HTTPException(status_code=400, detail=f"HTTP error occurred: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

