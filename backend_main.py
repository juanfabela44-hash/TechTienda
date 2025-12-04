import os
from datetime import datetime, timedelta
from typing import List, Optional
from enum import Enum

# Framework y utilidades
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# Base de datos (SQLAlchemy)
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, Session, declarative_base, relationship

# Seguridad
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- CONFIGURACIÓN ---
# En Railway, DATABASE_URL viene como variable de entorno.
# Si estás probando local, asegúrate de tener tu .env o setear esto.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db") 

# Ajuste para SQLAlchemy con Postgres en algunos proveedores (postgres:// vs postgresql://)
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "supersecreto_cambiar_en_produccion")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- BASE DE DATOS ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- MODELOS ORM (Tablas) ---
class User(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="comprador") # admin, vendedor, comprador
    products = relationship("Product", back_populates="owner")

class Product(Base):
    __tablename__ = "productos"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    description = Column(String)
    price = Column(Float, nullable=False)
    image_url = Column(String)
    seller_id = Column(Integer, ForeignKey("usuarios.id"))
    owner = relationship("User", back_populates="products")

# --- ESQUEMAS PYDANTIC (Validación) ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "comprador" # Opcional, por defecto comprador

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    class Config:
        orm_mode = True

class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    image_url: Optional[str] = None

class ProductCreate(ProductBase):
    pass

class ProductResponse(ProductBase):
    id: int
    seller_id: int
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

# --- SEGURIDAD ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- MAIN APP ---
app = FastAPI(title="TechMarket API")

# Crear tablas automáticamente (Para prototipado rápido, en prod usar Alembic)
Base.metadata.create_all(bind=engine)

# Configurar CORS (Permitir que el frontend acceda)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # En producción cambiar "*" por la URL de GitHub Pages
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- RUTAS DE AUTENTICACIÓN ---

@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    
    # Validar rol seguro
    if user.role not in ["admin", "vendedor", "comprador"]:
        user.role = "comprador"

    hashed_pw = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

# --- RUTAS DE PRODUCTOS ---

@app.get("/products", response_model=List[ProductResponse])
def read_products(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    products = db.query(Product).offset(skip).limit(limit).all()
    return products

@app.get("/my-products", response_model=List[ProductResponse])
def read_my_products(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role not in ["vendedor", "admin"]:
         raise HTTPException(status_code=403, detail="No tienes permisos de vendedor")
    return current_user.products

@app.post("/products", response_model=ProductResponse)
def create_product(product: ProductCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role not in ["vendedor", "admin"]:
        raise HTTPException(status_code=403, detail="Solo vendedores pueden crear productos")
    
    db_product = Product(**product.dict(), seller_id=current_user.id)
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product

@app.delete("/products/{product_id}")
def delete_product(product_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    
    # Solo el dueño o el admin puede borrar
    if current_user.role != "admin" and product.seller_id != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para borrar este producto")
    
    db.delete(product)
    db.commit()
    return {"detail": "Producto eliminado exitosamente"}