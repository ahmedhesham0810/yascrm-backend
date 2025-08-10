from fastapi import FastAPI, HTTPException
from sqlmodel import SQLModel, Field, create_engine, Session, select
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI()

# إعداد قاعدة البيانات SQLite (ملف test.db في مجلد المشروع)
sqlite_url = "sqlite:///./test.db"
engine = create_engine(sqlite_url, echo=True)

# إعداد التشفير لكلمات المرور
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# موديل المستخدم في قاعدة البيانات
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    password_hash: str

# موديل للبيانات الداخلة لتسجيل مستخدم جديد
class UserCreate(BaseModel):
    username: str
    password: str

# موديل للبيانات الداخلة لتسجيل الدخول
class UserLogin(BaseModel):
    username: str
    password: str

# إنشاء الجداول عند بدء تشغيل التطبيق
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

# دالة لتشفير كلمة المرور
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# دالة للتحقق من كلمة المرور المدخلة مقابل المشفرة في قاعدة البيانات
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# نقطة نهاية لإنشاء مستخدم جديد
@app.post("/users/")
def create_user(user: UserCreate):
    with Session(engine) as session:
        # التحقق من وجود المستخدم مسبقًا
        statement = select(User).where(User.username == user.username)
        existing_user = session.exec(statement).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="اسم المستخدم موجود بالفعل")

        # تشفير كلمة المرور وحفظ المستخدم
        user_obj = User(username=user.username, password_hash=get_password_hash(user.password))
        session.add(user_obj)
        session.commit()
        session.refresh(user_obj)
        return {"message": f"تم إنشاء المستخدم {user_obj.username} بنجاح."}

# نقطة نهاية لتسجيل الدخول
@app.post("/login/")
def login(user: UserLogin):
    with Session(engine) as session:
        statement = select(User).where(User.username == user.username)
        db_user = session.exec(statement).first()
        if not db_user or not verify_password(user.password, db_user.password_hash):
            raise HTTPException(status_code=400, detail="اسم المستخدم أو كلمة المرور غير صحيحة")

        return {"message": f"مرحبا {db_user.username}! تم تسجيل الدخول بنجاح."}

# نقطة نهاية اختبارية
@app.get("/")
def read_root():
    return {"message": "API تعمل بنجاح"}
