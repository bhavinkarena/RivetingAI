from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from decouple import config


SQLALCHEMY_DATABASE_URL = (
    "postgresql+psycopg2://"
    + config("DB_USERNAME")
    + ":"
    + config("DB_PASSWORD")
    + "@"
    + config("DB_HOST")
    + "/"
    + config("DB_NAME")
)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
