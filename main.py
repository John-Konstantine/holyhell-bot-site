import os
import random
import time
import requests
import logging
import httpx
from pathlib import Path
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from models import AdminLog
from fastapi import Body

from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.hash import bcrypt

from models import User, SessionLocal, fernet
from dotenv import load_dotenv
load_dotenv()


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
pending_admin_logins = {}  # login: {"code": str, "timestamp": float}
pending_admin_actions = {}  # login: {code, timestamp}

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "admin_actions.log"

def log_admin_action(admin_login: str, action: str, target_login: str, db: Session):
    messages = {
        "extend": "Продление подписки",
        "freeze": "Заморозка подписки",
        "delete": "Удаление пользователя"
    }
    action_str = messages.get(action, action)
    timestamp = datetime.now()

    # Сохраняем в базу
    db.add(AdminLog(
        admin_login=admin_login,
        action=action_str,
        target_login=target_login,
        timestamp=timestamp
    ))
    db.commit()

    # Сохраняем в файл
    line = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Администратор: {admin_login} | Действие: {action_str} | Пользователь: {target_login}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def check_admin_code(login: str, code: str):
    if login not in pending_admin_actions:
        return False
    expected = pending_admin_actions[login]
    if expected["code"] != code:
        return False
    if time.time() - expected["timestamp"] > 300:
        return False
    return True

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

    is_admin = user.telegram_id == "6393934084"  # Укажи свой Telegram ID

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
    key="login",
    value=login.encode('utf-8').hex(),
    httponly=False,
    secure=False,
    samesite="lax"
)

    if is_admin:
        code = f"{random.randint(100000, 999999)}"
        pending_admin_actions[login] = {"code": code, "timestamp": time.time()}

        try:
            url = f"https://api.telegram.org/bot{user.decrypt_telegram_token()}/sendMessage"
            requests.post(url, data={"chat_id": user.telegram_id, "text": f"Код подтверждения входа администратора: {code}"})
        except Exception as e:
            print("Ошибка Telegram:", e)

        response = RedirectResponse(url="/admin-confirm", status_code=303)
        response.set_cookie(
            key="login",
            value=login.encode('utf-8').hex(),
            httponly=False,
            secure=False,
            samesite="lax"
        )
        return response

    # ✅ Это нужно для обычных пользователей
    response.set_cookie(
        key="is_admin",
        value="False"
    )
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
RYPTOCLOUD_API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1dWlkIjoiTlRFME1EST0iLCJ0eXBlIjoicHJvamVjdCIsInYiOiI2ODllODcyMzA4MDQxMTEyZGM2ZjQzZTM2ZGEwMzVjMjFlMTA0M2E4NWY3ZThiMWI1YWNhMTRmNzUzYzk5ZGRjIiwiZXhwIjo4ODE0NTMwMjQ1Mn0.Cstegj5Y4rHCo9BTnKM_985Q06l5dziw6KDPHYsECHs"
CRYPTOCLOUD_PROJECT_ID = "A1BHwCXKDvWClDZ3"

async def create_invoice(login: str) -> str:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.cryptocloud.plus/v2/invoice/create",
                headers={
                    "Authorization": f"Token {CRYPTOCLOUD_API_KEY}",
                },
                data={
                    "amount": 30,
                    "currency": "USD",
                    "project_id": CRYPTOCLOUD_PROJECT_ID,
                    "custom_fields[login]": login
                }
            )
            result = response.json()
            if "url" in result:
                return result["url"]
            else:
                print("Ошибка при создании инвойса:", result)
                return "/payment-failed"
    except Exception as e:
        print("Исключение при создании инвойса:", str(e))
        return "/payment-failed"
    
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


from fastapi.responses import JSONResponse

@app.get("/debug/users")
def debug_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return JSONResponse(content=[{"id": u.id, "login": u.login} for u in users])

@app.get("/view_users", response_class=HTMLResponse)
def view_users(request: Request, db: Session = Depends(get_db)):
    users = db.query(User).all()

    log_entries = db.query(AdminLog).order_by(AdminLog.timestamp.desc()).limit(100).all()

    return templates.TemplateResponse("view_users.html", {
        "request": request,
        "users": users,
        "log_entries": log_entries
    })

@app.post("/admin/send-code")
def send_admin_code(
    request: Request,
    login: str = Form(...),
    db: Session = Depends(get_db)
):
    # Получаем администратора
    login_hex = request.cookies.get("login")
    try:
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else None
    except:
        admin_login = None

    admin = db.query(User).filter(User.login == admin_login).first()
    if not admin:
        raise HTTPException(status_code=403, detail="Нет доступа")

    # Генерация кода для подтверждения
    code = f"{random.randint(100000, 999999)}"
    pending_admin_actions[login] = {"code": code, "timestamp": time.time()}

    try:
        token = admin.decrypt_telegram_token()
        chat_id = admin.telegram_id
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        text = f"Код подтверждения: {code}"
        requests.post(url, data={"chat_id": chat_id, "text": text})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка Telegram: {e}")

    return RedirectResponse(url="/view_users", status_code=303)

@app.post("/admin/extend")
def extend_by_admin(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    if not check_admin_code(login, code):
        raise HTTPException(status_code=400, detail="Неверный или просроченный код")

    user = db.query(User).filter(User.login == login).first()
    if user:
        if user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow():
            user.subscription_expires_at += timedelta(days=30)
        else:
            user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)
        db.commit()

        login_hex = request.cookies.get("login")
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else "неизвестен"
        log_admin_action(admin_login, "extend", login, db)

    return RedirectResponse(url="/view_users", status_code=303)

@app.post("/admin/freeze")
def freeze_by_admin(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    if not check_admin_code(login, code):
        raise HTTPException(status_code=400, detail="Неверный или просроченный код")

    user = db.query(User).filter(User.login == login).first()
    if user:
        user.subscription_expires_at = None
        db.commit()

        login_hex = request.cookies.get("login")
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else "неизвестен"
        log_admin_action(admin_login, "freeze", login, db)

    return RedirectResponse(url="/view_users", status_code=303)

@app.post("/admin/delete")
def delete_by_admin(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    if not check_admin_code(login, code):
        raise HTTPException(status_code=400, detail="Неверный или просроченный код")

    user = db.query(User).filter(User.login == login).first()
    if user:
        db.delete(user)
        db.commit()

        login_hex = request.cookies.get("login")
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else "неизвестен"
        log_admin_action(admin_login, "delete", login, db)

    return RedirectResponse(url="/view_users", status_code=303)

@app.get("/admin-confirm", response_class=HTMLResponse)
def show_admin_confirm_page(request: Request):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else None
    except:
        login = None

    code_data = pending_admin_actions.get(login)
    if code_data:
        remaining = max(0, int(300 - (time.time() - code_data["timestamp"])))
    else:
        remaining = 0

    return templates.TemplateResponse("admin_confirm.html", {
        "request": request,
        "error": None,
        "debug": {
            "remaining": remaining
        }
    })

@app.get("/payment-success", response_class=HTMLResponse)
def payment_success(request: Request):
    return templates.TemplateResponse("payment_success.html", {"request": request})


@app.get("/payment-failed", response_class=HTMLResponse)
def payment_failed(request: Request):
    return templates.TemplateResponse("payment_failed.html", {"request": request})

@app.post("/webhook/payment")
async def payment_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        print("Webhook получен:", data)

        # Проверка статуса оплаты
        if data.get("status") != "success":
            return {"ok": True}

        login = data.get("custom_fields", {}).get("login")
        if not login:
            return {"error": "Логин не передан"}

        user = db.query(User).filter(User.login == login).first()
        if not user:
            return {"error": "Пользователь не найден"}

        # Продлеваем подписку
        if user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow():
            user.subscription_expires_at += timedelta(days=30)
        else:
            user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)

        db.commit()

        return {"ok": True}
    except Exception as e:
        print("Ошибка вебхука:", e)
        return {"error": str(e)}

@app.get("/pay")
async def redirect_to_payment(request: Request):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode("utf-8")
    except:
        login = None

    if not login:
        return RedirectResponse(url="/login")

    invoice_url = await create_invoice(login)
    return RedirectResponse(url=invoice_url)

@app.post("/admin-confirm", response_class=HTMLResponse)
def confirm_admin_code(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode('utf-8') if login_hex else None
    except:
        login = None

    if not login or login not in pending_admin_actions:  # <--- вот тут было logins, стало actions
        return templates.TemplateResponse("admin_confirm.html", {
            "request": request,
            "error": "Доступ запрещён или код не запрашивался",
            "debug": {
                "remaining": "-"
            }
        })

    expected = pending_admin_actions.get(login)
    if expected["code"] != code or time.time() - expected["timestamp"] > 300:
        remaining = max(0, int(300 - (time.time() - expected["timestamp"])))
        return templates.TemplateResponse("admin_confirm.html", {
            "request": request,
            "error": "Неверный или просроченный код",
            "debug": {
                "remaining": remaining
            }
        })

    # Успешно подтверждено
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="is_admin", value="True")
    return response
