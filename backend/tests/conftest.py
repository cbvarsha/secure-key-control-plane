import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ['DATABASE_URL']='sqlite:///:memory:'
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base
import app.models

@pytest.fixture
def db():
    eng=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool);Base.metadata.create_all(eng);S=sessionmaker(bind=eng,expire_on_commit=False);s=S()
    try:yield s
    finally:s.close();Base.metadata.drop_all(eng)
