from sqlmodel import SQLModel, Field
from typing import Optional
from sqlalchemy import Column, String
import datetime
from uuid import uuid4
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    username: str = Field(sa_column=Column(String, unique=True, nullable=False))
    password_hash: str
    role: str = Field(default="sales")
    is_active: bool = Field(default=True)
    force_password_change: bool = Field(default=False)
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    last_login_at: Optional[datetime.datetime] = None

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)

    def set_password(self, password: str):
        self.password_hash = pwd_context.hash(password)
