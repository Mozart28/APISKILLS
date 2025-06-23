from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from typing import Optional, List
from datetime import datetime, timedelta
from sqlmodel import Field, SQLModel, Session, create_engine, select

# --- Config JWT ---
SECRET_KEY = "a_very_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- DB setup ---
DATABASE_URL = "sqlite:///./skills.db"
engine = create_engine(DATABASE_URL, echo=True)

# --- App init ---
app = FastAPI()

# --- Models ---
class Token(BaseModel):
    access_token: str
    token_type: str

class User(SQLModel, table=True):
    username: str = Field(primary_key=True)
    full_name: Optional[str]
    hashed_password: str

class Skill(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    level: int

class SkillCreate(BaseModel):
    name: str
    level: int

# --- Auth utils ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password

def get_user(username: str):
    with Session(engine) as session:
        user = session.get(User, username)
        return user

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

# --- Routes ---
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    # Ajouter un utilisateur par défaut si non présent
    with Session(engine) as session:
        if not session.get(User, "mozart"):
            session.add(User(username="mozart", full_name="Mozart Codjo", hashed_password="1234"))
            session.commit()

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/skills", response_model=List[Skill])
def read_skills(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        skills = session.exec(select(Skill)).all()
        return skills

@app.post("/skills", response_model=Skill)
def add_skill(skill: SkillCreate, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        db_skill = Skill(name=skill.name, level=skill.level)
        session.add(db_skill)
        session.commit()
        session.refresh(db_skill)
        return db_skill
