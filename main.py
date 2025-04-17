from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from models import User, SessionLocal, fernet
from passlib.hash import bcrypt
from datetime import datetime, timedelta
import os
import random
import time
import requests

# ❗ ВРЕМЕННОЕ УДАЛЕНИЕ БАЗЫ ПРИ СТАРТЕ (чтобы убрать ошибку InvalidToken)
if os.path.exists("database.db"):
    os.remove("database.db")


app = FastAPI(
    title="Сайт торгового бота",
    description="Сервер для хранения и выдачи ключей пользователям",
    version="1.0.0",
    debug=True
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
app.mount("/downloads", StaticFiles(directory=os.path.join(BASE_DIR, "downloads")), name="downloads")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pending_hwid_resets = {}

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# --------------------------- РЕГИСТРАЦИЯ ---------------------------

@app.get("/register", response_class=HTMLResponse)
def show_register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register_user_form(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    api_key: str = Form(...),
    api_secret: str = Form(...),
    telegram_id: str = Form(...),
    telegram_token: str = Form(...),
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.login == login).first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким логином уже существует"
        })

    password_hash = bcrypt.hash(password)
    encrypted_secret = fernet.encrypt(api_secret.encode()).decode()
    encrypted_token = fernet.encrypt(telegram_token.encode()).decode()

    new_user = User(
        login=login,
        password_hash=password_hash,
        api_key=api_key,
        api_secret_encrypted=encrypted_secret,
        telegram_id=telegram_id,
        telegram_token_encrypted=encrypted_token,
        subscription_expires_at=datetime.utcnow() + timedelta(days=30)
    )

    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/login", status_code=303)

# --------------------------- HTML-ФОРМА ВХОДА (БЕЗ HWID) ---------------------------

@app.get("/login", response_class=HTMLResponse)
def show_login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
def login_user_form(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.login == login).first()
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Пользователь не найден"})

    if not bcrypt.verify(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный пароль"})

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="login", value=login.encode('utf-8').hex())
    return response


# --------------------------- JSON-API для ПРИЛОЖЕНИЯ (с HWID) ---------------------------

class LoginRequest(BaseModel):
    login: str
    password: str
    hwid: str

class LoginResponse(BaseModel):
    api_key: str
    api_secret: str
    telegram_id: str
    telegram_token: str

@app.post("/api/login", response_model=LoginResponse)
def login_via_app(request: LoginRequest, db: Session = Depends(get_db)):
    print("ПОЛУЧЕННЫЕ ДАННЫЕ:", request.login, request.password, request.hwid)
    user = db.query(User).filter(User.login == request.login).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if not bcrypt.verify(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверный пароль")

    if not user.hwid:
        user.hwid = request.hwid
        db.commit()
    elif user.hwid != request.hwid:
        raise HTTPException(status_code=403, detail="Доступ с другого устройства запрещён")

    return LoginResponse(
        api_key=user.api_key,
        api_secret=user.decrypt_api_secret(),
        telegram_id=user.telegram_id,
        telegram_token=user.decrypt_telegram_token()
    )

# --------------------------- DASHBOARD и HWID RESET (остаются) ---------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def show_dashboard(request: Request, db: Session = Depends(get_db)):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode('utf-8') if login_hex else None
    except:
        login = None

    if not login:
        return RedirectResponse(url="/login")

    user = db.query(User).filter(User.login == login).first()
    if not user:
        return RedirectResponse(url="/login")

    subscription_active = user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "login": user.login,
        "api_key": user.api_key,
        "api_secret": user.decrypt_api_secret(),
        "telegram_id": user.telegram_id,
        "telegram_token": user.decrypt_telegram_token(),
        "subscription_expires": user.subscription_expires_at.strftime('%Y-%m-%d %H:%M:%S') if user.subscription_expires_at else "нет",
        "subscription_active": subscription_active
    })

@app.post("/request-hwid-reset", response_class=HTMLResponse)
def request_hwid_reset(
    request: Request,
    login: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.login == login).first()
    if not user:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": "Пользователь не найден"
        })

    code = f"{random.randint(100000, 999999)}"
    pending_hwid_resets[login] = {"code": code, "timestamp": time.time()}

    try:
        url = f"https://api.telegram.org/bot{user.decrypt_telegram_token()}/sendMessage"
        data = {"chat_id": user.telegram_id, "text": f"Код для сброса HWID: {code}"}
        requests.post(url, data=data)
    except Exception as e:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": f"Ошибка при отправке в Telegram: {e}"
        })

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "login": login,
        "api_key": user.api_key,
        "api_secret": user.decrypt_api_secret(),
        "telegram_id": user.telegram_id,
        "telegram_token": user.decrypt_telegram_token(),
        "show_code_input": True
    })

@app.post("/confirm-hwid-reset", response_class=HTMLResponse)
def confirm_hwid_reset(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    expected = pending_hwid_resets.get(login)
    if not expected or expected["code"] != code or time.time() - expected["timestamp"] > 300:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": "Неверный или просроченный код"
        })

    user = db.query(User).filter(User.login == login).first()
    if not user:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": "Пользователь не найден"
        })

    user.hwid = None
    db.commit()
    pending_hwid_resets.pop(login, None)

    subscription_active = user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "login": user.login,
        "api_key": user.api_key,
        "api_secret": user.decrypt_api_secret(),
        "telegram_id": user.telegram_id,
        "telegram_token": user.decrypt_telegram_token(),
        "hwid_reset_success": True,
        "subscription_expires": user.subscription_expires_at.strftime('%Y-%m-%d %H:%M:%S') if user.subscription_expires_at else "нет",
        "subscription_active": subscription_active
    })

@app.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("login")
    return response

@app.post("/extend-subscription")
def extend_subscription(request: Request, login: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.login == login).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow():
        user.subscription_expires_at += timedelta(days=30)
    else:
        user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)

    db.commit()

    return RedirectResponse(url="/dashboard", status_code=303)


