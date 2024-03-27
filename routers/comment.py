from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from database import SessionLocal

from datetime import datetime


from fastapi import APIRouter, Depends, File, Form, HTTPException, Request
from sqlalchemy.orm import Session as DBSession
from utils_file.apiError import ApiError
from utils_file.apiResponse import ApiResponse
from database import SessionLocal
from models import Comment
import schemas
from routers.crud import (
    get_comment_count_by_document_id,
    get_user_by_token,
    get_comment_by_id,
    get_comments_by_document_id,
    get_document_by_id,
)
import schemas


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = APIRouter()


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
    return ApiResponse(
        statusCode=200,
        data={
            "id": comment.id,
            "text": comment.text,
            "user_id": comment.user_id,
            "document_id": comment.document_id,
            "created_at": comment.created_at,
        },
        message="Comment created successfully",
    )


@app.post("/comments/{comment_id}/replies")
async def create_reply(
    comment: schemas.CommentCreate,
    comment_id: int,
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: DBSession = Depends(get_db),
):
    # Check if the parent comment exists
    parent_comment = get_comment_by_id(db, comment_id=comment_id)
    if not parent_comment:
        raise HTTPException(status_code=404, detail="Parent comment not found")

    token = creds.credentials
    print("token :-", token)
    user = get_user_by_token(db, token=token)

    # Create the reply comment
    reply_comment = Comment(
        text=comment.text,
        user_id=user.id,  # Assuming 'user' is available in the current context
        document_id=parent_comment.document_id,
        parent_comment_id=comment_id,
        created_at=datetime.now(),
    )
    db.add(reply_comment)
    db.commit()
    db.refresh(reply_comment)

    return ApiResponse(
        statusCode=200,
        data={
            "id": reply_comment.id,
            "text": reply_comment.text,
            "user_id": reply_comment.user_id,
            "document_id": reply_comment.document_id,
            "parent_comment_id": reply_comment.parent_comment_id,
            "created_at": reply_comment.created_at,
        },
        message="Reply comment created successfully",
    )


@app.get("/documents/{document_id}/comments")
async def get_comments_for_document(document_id: int, db: DBSession = Depends(get_db)):
    comments = get_comments_by_document_id(db, document_id=document_id)
    return ApiResponse(
        statusCode=200,
        data=[
            {
                "id": comment.id,
                "text": comment.text,
                "user_id": comment.user_id,
                "document_id": comment.document_id,
                "parent_comment_id": comment.parent_comment_id,
                "created_at": comment.created_at,
            }
            for comment in comments
        ],
        message="Comments retrieved successfully",
    )


@app.delete("/comments/delete/{comment_id}")
async def delete_comment(comment_id: int, db: DBSession = Depends(get_db)):
    comment = get_comment_by_id(db, comment_id=comment_id)
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    def delete_comment_recursive(comment_id):
        comment = get_comment_by_id(db, comment_id=comment_id)
        if not comment:
            return

        replies = (
            db.query(Comment).filter(Comment.parent_comment_id == comment_id).all()
        )
        print(replies)
        for reply in replies:
            delete_comment_recursive(reply.id)
        db.delete(comment)
        db.commit()

    delete_comment_recursive(comment_id)

    return ApiResponse(
        statusCode=200,
        data={"id": comment_id},
        message="Comment deleted successfully",
    )


@app.put("/comments/{comment_id}/edit")
async def edit_comment(
    comment_id: int,
    edited_comment: schemas.CommentCreate,
    creds: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: DBSession = Depends(get_db),
):
    # Get the comment from the database
    comment = get_comment_by_id(db, comment_id=comment_id)
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Check if the user is authenticated and get their user ID
    token = creds.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = get_user_by_token(db, token=token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Check if the user is the author of the comment
    if comment.user_id != user.id:
        raise HTTPException(
            status_code=403, detail="You can only edit your own comments"
        )

    # Update the comment text
    comment.text = edited_comment.text
    db.commit()
    return ApiResponse(
        statusCode=200,
        data={"id": comment_id, "text": comment.text},
        message="Comment edited successfully",
    )


@app.post("/comments/count/{document_id}")
async def get_comment_count(document_id: int, db: DBSession = Depends(get_db)):
    comment_count = get_comment_count_by_document_id(db, document_id=document_id)
    if not comment_count:
        raise HTTPException(status_code=404, detail="Document not found")
    else:
        return ApiResponse(
            statusCode=200,
            data={"comment_count": comment_count},
            message="Comment count retrieved successfully",
        )
