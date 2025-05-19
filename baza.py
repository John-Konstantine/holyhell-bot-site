import os
import random
import time
import requests
import logging
import httpx
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, Depends, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from passlib.hash import bcrypt
from pydantic import BaseModel
from models import User, SessionLocal, fernet, AdminLog, Base, Payment, PendingInvoice
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv

# Настройка логирования для файла и консоли
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Логи в файл
file_handler = logging.FileHandler("app.log")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Логи в консоль
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

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

# Функция отправки уведомлений о подписке
def send_subscription_alerts():
    """
    Каждые 3 часа проверяем, у кого до конца подписки осталось 1–4 дня,
    и шлём Telegram-уведомление.
    """
    now = datetime.utcnow()
    db = SessionLocal()
    try:
        users = (
            db.query(User)
              .filter(
                  User.subscription_expires_at > now,
                  User.subscription_expires_at < now + timedelta(days=8)
              )
              .all()
        )
        for user in users:
            days_left = (user.subscription_expires_at - now).days
            if days_left > 0:
                token = user.decrypt_telegram_token()
                chat_id = user.telegram_id
                text = (
                    f"❗️ Ваша подписка истекает через {days_left} "
                    f"дней (до {user.subscription_expires_at.strftime('%Y-%m-%d')}). "
                    f"Пожалуйста, продлите подписку в личном кабинете."
                )
                try:
                    response = requests.post(
                        f"https://api.telegram.org/bot{token}/sendMessage",
                        data={"chat_id": chat_id, "text": text}
                    )
                    response.raise_for_status()
                    logging.info(f"[SubAlert] {user.login}: осталось {days_left} дн.")
                except requests.exceptions.RequestException as e:
                    logging.error(f"[SubAlert] ошибка для {user.login}: {e}")
    except Exception as e:
        logging.error(f"[SubAlert] Общая ошибка: {e}")
    finally:
        db.close()

# Настройка APScheduler: оповещения о подписке каждые 3 часа
scheduler = BackgroundScheduler(timezone=timezone.utc)
scheduler.add_job(
    send_subscription_alerts,
    trigger=IntervalTrigger(hours=3),
    id='subscription_alerts',
    replace_existing=True
)

@app.on_event("startup")
def start_scheduler():
    send_subscription_alerts()  # Первый запуск сразу
    scheduler.start()

@app.on_event("shutdown")
def shutdown_scheduler():
    scheduler.shutdown()

# Загрузка секретов из .env
CRYPTOCLOUD_API_KEY = os.getenv("CRYPTOCLOUD_API_KEY")
CRYPTOCLOUD_PROJECT_ID = os.getenv("CRYPTOCLOUD_PROJECT_ID")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pending_hwid_resets = {}
pending_admin_logins = {}
pending_admin_actions = {}
pending_password_resets = {}  

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
    timestamp = datetime.now(timezone.utc)

    logging.info(f"Админ {admin_login} выполнил действие '{action_str}' для {target_login}")

    db.add(AdminLog(
        admin_login=admin_login,
        action=action_str,
        target_login=target_login,
        timestamp=timestamp
    ))
    db.commit()

    line = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Администратор: {admin_login} | Действие: {action_str} | Пользователь: {target_login}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def check_admin_code(login: str, code: str):
    if login not in pending_admin_actions:
        logging.error(f"Проверка кода для {login} невозможна: запись отсутствует в pending_admin_actions")
        return False
    expected = pending_admin_actions[login]
    if expected["code"] != code:
        logging.error(f"Неверный код для {login}: ожидался {expected['code']}, получен {code}")
        return False
    if time.time() - expected["timestamp"] > 300:
        logging.error(f"Код для {login} просрочен")
        return False
    logging.info(f"Код для {login} успешно проверен")
    return True

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    logging.info("Открыта главная страница")
    return templates.TemplateResponse("nachalo.html", {"request": request})

# --------------------------- РЕГИСТРАЦИЯ ---------------------------

@app.get("/register", response_class=HTMLResponse)
def show_register_form(request: Request):
    logging.info("Открыта форма регистрации")
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
    logging.info(f"Попытка регистрации пользователя {login}")
    if db.query(User).filter(User.login == login).first():
        logging.error(f"Регистрация отклонена: логин {login} уже существует")
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким логином уже существует"
        })
    if db.query(User).filter(User.telegram_id == telegram_id).first():
        logging.error(f"Регистрация отклонена: Telegram ID {telegram_id} уже зарегистрирован")
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким Telegram ID уже существует"
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
    logging.info(f"Пользователь {login} успешно зарегистрирован")
    return RedirectResponse(url="/login", status_code=303)

# --------------------------- HTML-ФОРМА ВХОДА (БЕЗ HWID) ---------------------------

@app.get("/login", response_class=HTMLResponse)
def show_login_form(request: Request):
    logging.info("Открыта форма входа")
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
def login_user_form(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    logging.info(f"Попытка входа для {login}")
    user = db.query(User).filter(User.login == login).first()
    if not user:
        logging.error(f"Вход отклонён: пользователь {login} не найден")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Пользователь не найден"})

    if not bcrypt.verify(password, user.password_hash):
        logging.error(f"Вход отклонён: неверный пароль для {login}")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный пароль"})

    is_admin = user.telegram_id == "6393934084"  # Укажи свой Telegram ID
    logging.info(f"Пользователь {login} аутентифицирован, is_admin={is_admin}")

    response = RedirectResponse(url="/lichny_kabinet", status_code=303)
    response.set_cookie(
        key="login",
        value=login.encode('utf-8').hex(),
        httponly=True,
        secure=True,
        samesite="strict"
    )

    if is_admin:
        code = f"{random.randint(100000, 999999)}"
        pending_admin_actions[login] = {"code": code, "timestamp": time.time()}
        logging.info(f"Сгенерирован код администратора для {login}: {code}")

        try:
            url = f"https://api.telegram.org/bot{user.decrypt_telegram_token()}/sendMessage"
            response = requests.post(url, data={"chat_id": user.telegram_id, "text": f"Код подтверждения входа администратора: {code}"})
            response.raise_for_status()
            logging.info(f"Код отправлен в Telegram для {login}")
        except Exception as e:
            logging.error(f"Ошибка отправки кода в Telegram для {login}: {e}")

        response = RedirectResponse(url="/admin-confirm", status_code=303)
        response.set_cookie(
            key="login",
            value=login.encode('utf-8').hex(),
            httponly=True,
            secure=True,
            samesite="strict"
        )
        return response

    response.set_cookie(
        key="is_admin",
        value="False",
        httponly=True,
        secure=True,
        samesite="strict"
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
    binance_api_key: str
    binance_api_secret: str

@app.post("/api/login", response_model=LoginResponse)
def login_via_app(request: LoginRequest, db: Session = Depends(get_db)):
    logging.info(f"API вход: {request.login}, HWID: {request.hwid}")
    user = db.query(User).filter(User.login == request.login).first()
    if not user:
        logging.error(f"API вход отклонён: пользователь {request.login} не найден")
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if not bcrypt.verify(request.password, user.password_hash):
        logging.error(f"API вход отклонён: неверный пароль для {request.login}")
        raise HTTPException(status_code=401, detail="Неверный пароль")

    if not user.subscription_expires_at or user.subscription_expires_at < datetime.utcnow():
        logging.error(f"API вход отклонён: подписка для {request.login} неактивна")
        raise HTTPException(status_code=403, detail="Подписка неактивна или истекла")

    if not user.hwid:
        user.hwid = request.hwid
        db.commit()
        logging.info(f"HWID для {request.login} установлен: {request.hwid}")
    elif user.hwid != request.hwid:
        logging.error(f"API вход отклонён: HWID не совпадает для {request.login}, ожидался {user.hwid}, получен {request.hwid}")
        raise HTTPException(status_code=403, detail="Доступ с другого устройства запрещён")

    logging.info(f"API вход успешен для {request.login}")
    return LoginResponse(
        api_key=user.api_key,
        api_secret=user.decrypt_api_secret(),
        telegram_id=user.telegram_id,
        telegram_token=user.decrypt_telegram_token(),
        binance_api_key=user.api_key,
        binance_api_secret=user.decrypt_api_secret()
    )

# --------------------------- DASHBOARD и HWID RESET ---------------------------

@app.get("/lichny_kabinet", response_class=HTMLResponse)
def show_lichny_kabinet(request: Request, db: Session = Depends(get_db)):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode('utf-8') if login_hex else None
    except Exception as e:
        logging.error(f"Ошибка декодирования login из cookies: {e}")
        login = None

    if not login:
        logging.info("Перенаправление на страницу входа: логин отсутствует")
        return RedirectResponse(url="/login")

    user = db.query(User).filter(User.login == login).first()
    if not user:
        logging.error(f"Перенаправление на страницу входа: пользователь {login} не найден")
        return RedirectResponse(url="/login")

    subscription_active = bool(
        user.subscription_expires_at
        and user.subscription_expires_at > datetime.utcnow()
    )
    logging.info(f"Открыт дашборд для {login}, подписка активна: {subscription_active}")

    return templates.TemplateResponse("lichny_kabinet.html", {
        "request": request,
        "login": user.login,
        "api_key": user.api_key,
        "api_secret": user.decrypt_api_secret(),
        "telegram_id": user.telegram_id,
        "telegram_token": user.decrypt_telegram_token(),
        "subscription_expires": user.subscription_expires_at.strftime('%Y-%m-%d %H:%M:%S') if user.subscription_expires_at else "нет",
        "subscription_active": subscription_active
    })

async def create_invoice(login: str, db: Session = Depends(get_db)) -> str:
    logging.info(f"Создание инвойса для {login}")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.cryptocloud.plus/v2/invoice/create",
                headers={"Authorization": f"Token {CRYPTOCLOUD_API_KEY}"},
                json={
                    "amount": 30,
                    "currency": "USD",
                    "shop_id": CRYPTOCLOUD_PROJECT_ID,
                    "custom_fields": {"login": login}
                }
            )
            result = response.json()
            logging.info(f"Ответ от CryptoCloud: {json.dumps(result, indent=2, ensure_ascii=False)}")
            result_data = result.get("result") or {}
            link = result_data.get("link")
            invoice_id = result_data.get("uuid")
            if result.get("status") == "success" and link:
                invoice_id_clean = invoice_id.replace("INV-", "")
                pending_invoice = PendingInvoice(invoice_id=invoice_id_clean, user_login=login)
                db.add(pending_invoice)
                db.commit()
                logging.info(f"Инвойс успешно создан для {login}, ссылка: {link}, invoice_id: {invoice_id_clean}")
                return link
            else:
                logging.error(f"Ошибка при создании инвойса для {login}: {json.dumps(result, indent=2, ensure_ascii=False)}")
                return "/payment-failed"
    except Exception as e:
        logging.error(f"Исключение при создании инвойса для {login}: {str(e)}")
        return "/payment-failed"

@app.post("/request-hwid-reset", response_class=HTMLResponse)
def request_hwid_reset(
    request: Request,
    login: str = Form(...),
    db: Session = Depends(get_db)
):
    logging.info(f"Запрос сброса HWID для {login}")
    user = db.query(User).filter(User.login == login).first()
    if not user:
        logging.error(f"Сброс HWID отклонён: пользователь {login} не найден")
        return templates.TemplateResponse("lichny_kabinet.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": "Пользователь не найден"
        })

    code = f"{random.randint(100000, 999999)}"
    pending_hwid_resets[login] = {"code": code, "timestamp": time.time()}
    logging.info(f"Сгенерирован код сброса HWID для {login}: {code}")

    try:
        url = f"https://api.telegram.org/bot{user.decrypt_telegram_token()}/sendMessage"
        data = {"chat_id": user.telegram_id, "text": f"Код для сброса HWID: {code}"}
        response = requests.post(url, data=data)
        response.raise_for_status()
        logging.info(f"Код сброса HWID отправлен в Telegram для {login}")
    except Exception as e:
        logging.error(f"Ошибка отправки кода в Telegram для {login}: {e}")
        return templates.TemplateResponse("lichny_kabinet.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": f"Ошибка при отправке в Telegram: {e}"
        })

    return templates.TemplateResponse("lichny_kabinet.html", {
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
    logging.info(f"Подтверждение сброса HWID для {login}, код: {code}")
    expected = pending_hwid_resets.get(login)
    if not expected or expected["code"] != code or time.time() - expected["timestamp"] > 300:
        logging.error(f"Сброс HWID отклонён для {login}: неверный или просроченный код")
        return templates.TemplateResponse("lichny_kabinet.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": "Неверный или просроченный код"
        })

    user = db.query(User).filter(User.login == login).first()
    if not user:
        logging.error(f"Сброс HWID отклонён: пользователь {login} не найден")
        return templates.TemplateResponse("lichny_kabinet.html", {
            "request": request,
            "login": login,
            "hwid_reset_error": "Пользователь не найден"
        })

    user.hwid = None
    db.commit()
    pending_hwid_resets.pop(login, None)
    logging.info(f"HWID успешно сброшено для {login}")

    subscription_active = bool(
        user.subscription_expires_at
        and user.subscription_expires_at > datetime.utcnow()
    )

    return templates.TemplateResponse("lichny_kabinet.html", {
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
    logging.info("Пользователь выполнил выход")
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("login")
    return response

@app.post("/extend-subscription")
def extend_subscription(request: Request, login: str = Form(...), db: Session = Depends(get_db)):
    logging.info(f"Продление подписки для {login}")
    user = db.query(User).filter(User.login == login).first()
    if not user:
        logging.error(f"Продление подписки отклонено: пользователь {login} не найден")
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow():
        user.subscription_expires_at += timedelta(days=30)
    else:
        user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)

    db.commit()
    logging.info(f"Подписка продлена для {login} до {user.subscription_expires_at}")

    return RedirectResponse(url="/lichny_kabinet", status_code=303)

@app.get("/debug/users")
def debug_users(db: Session = Depends(get_db)):
    logging.info("Запрос списка пользователей для отладки")
    users = db.query(User).all()
    return JSONResponse(content=[{"id": u.id, "login": u.login} for u in users])

@app.get("/view_users", response_class=HTMLResponse)
def view_users(request: Request, db: Session = Depends(get_db)):
    logging.info("Открыта страница просмотра пользователей")
    users = db.query(User).all()
    log_entries = db.query(AdminLog).order_by(AdminLog.timestamp.desc()).limit(100).all()
    return templates.TemplateResponse("admin_panel.html", {
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
    login_hex = request.cookies.get("login")
    try:
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else None
    except Exception as e:
        logging.error(f"Ошибка декодирования admin_login из cookies: {e}")
        admin_login = None

    logging.info(f"Запрос кода администратора для {login} от {admin_login}")
    admin = db.query(User).filter(User.login == admin_login).first()
    if not admin:
        logging.error(f"Запрос кода отклонён: админ {admin_login} не найден")
        raise HTTPException(status_code=403, detail="Нет доступа")

    code = f"{random.randint(100000, 999999)}"
    pending_admin_actions[login] = {"code": code, "timestamp": time.time()}
    logging.info(f"Сгенерирован код для {login}: {code}")

    try:
        token = admin.decrypt_telegram_token()
        chat_id = admin.telegram_id
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        text = f"Код подтверждения: {code}"
        response = requests.post(url, data={"chat_id": chat_id, "text": text})
        response.raise_for_status()
        logging.info(f"Код отправлен в Telegram для {admin_login}")
    except Exception as e:
        logging.error(f"Ошибка Telegram для {admin_login}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка Telegram: {e}")

    return RedirectResponse(url="/view_users", status_code=303)

@app.post("/admin/extend")
def extend_by_admin(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    logging.info(f"Продление подписки админом для {login}, код: {code}")
    if not check_admin_code(login, code):
        logging.error(f"Продление отклонено для {login}: неверный или просроченный код")
        raise HTTPException(status_code=400, detail="Неверный или просроченный код")

    user = db.query(User).filter(User.login == login).first()
    if user:
        if user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow():
            user.subscription_expires_at += timedelta(days=30)
        else:
            user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)
        db.commit()
        logging.info(f"Подписка продлена админом для {login} до {user.subscription_expires_at}")

        login_hex = request.cookies.get("login")
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else "неизвестен"
        log_admin_action(admin_login, "extend", login, db)

    return RedirectResponse(url="/view_users", status_code=303)

@app.post("/admin/remove-subscription")
def remove_subscription_by_admin(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    logging.info(f"Удаление подписки админом для {login}, код: {code}")
    if not check_admin_code(login, code):
        logging.error(f"Удаление подписки отклонено для {login}: неверный или просроченный код")
        raise HTTPException(status_code=400, detail="Неверный или просроченный код")

    user = db.query(User).filter(User.login == login).first()
    if user:
        user.subscription_expires_at = None
        db.commit()
        logging.info(f"Подписка удалена для {login}")

        login_hex = request.cookies.get("login")
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else "неизвестен"
        log_admin_action(admin_login, "remove_subscription", login, db)

    return RedirectResponse(url="/view_users", status_code=303)

@app.post("/admin/delete")
def delete_by_admin(
    request: Request,
    login: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    logging.info(f"Удаление пользователя админом для {login}, код: {code}")
    if not check_admin_code(login, code):
        logging.error(f"Удаление отклонено для {login}: неверный или просроченный код")
        raise HTTPException(status_code=400, detail="Неверный или просроченный код")

    user = db.query(User).filter(User.login == login).first()
    if user:
        db.delete(user)
        db.commit()
        logging.info(f"Пользователь {login} удалён админом")

        login_hex = request.cookies.get("login")
        admin_login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else "неизвестен"
        log_admin_action(admin_login, "delete", login, db)

    return RedirectResponse(url="/view_users", status_code=303)

@app.get("/admin-confirm", response_class=HTMLResponse)
def show_admin_confirm_page(request: Request):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode("utf-8") if login_hex else None
    except Exception as e:
        logging.error(f"Ошибка декодирования login из cookies: {e}")
        login = None

    logging.info(f"Открыта страница подтверждения админа для {login}")
    code_data = pending_admin_actions.get(login)
    if code_data:
        remaining = max(0, int(300 - (time.time() - code_data["timestamp"])))
    else:
        remaining = 0

    return templates.TemplateResponse("cod_TG.html", {
        "request": request,
        "error": None,
        "debug": {
            "remaining": remaining
        }
    })

@app.get("/pay_okey", response_class=HTMLResponse)
def pay_okey(request: Request):
    logging.info("Открыта страница успешного платежа")
    return templates.TemplateResponse("pay_okey.html", {"request": request})

@app.get("/pay_fail", response_class=HTMLResponse)
def payment_failed(request: Request):
    logging.info("Открыта страница неудачного платежа")
    return templates.TemplateResponse("pay_fail.html", {"request": request})

@app.post("/webhook/payment")
async def payment_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        form = await request.form()
        data = dict(form)
        logging.info(f"Webhook получен: {json.dumps(data, ensure_ascii=False)}")

        if data.get("status") != "success":
            logging.info("Платёж не успешен, пропускаем")
            return {"ok": True}

        invoice_id = data.get("invoice_id")
        if not invoice_id:
            logging.error("invoice_id отсутствует в вебхуке")
            return {"error": "invoice_id отсутствует"}

        if db.query(Payment).filter(Payment.invoice_id == invoice_id).first():
            logging.info(f"Платёж {invoice_id} уже обработан")
            return {"ok": True}

        login = None
        pending_invoice = db.query(PendingInvoice).filter(PendingInvoice.invoice_id == invoice_id).first()
        if pending_invoice:
            login = pending_invoice.user_login
            logging.info(f"Логин извлечён из PendingInvoice: {login}, invoice_id: {invoice_id}")
        else:
            logging.warning(f"PendingInvoice не найден для invoice_id: {invoice_id}")
            if "custom_fields" in data:
                try:
                    custom_fields = data["custom_fields"]
                    login = json.loads(custom_fields)["login"] if isinstance(custom_fields, str) else custom_fields["login"]
                    logging.info(f"Логин извлечён из custom_fields: {login}")
                except (ValueError, KeyError) as e:
                    logging.error(f"Ошибка парсинга custom_fields: {e}")
                    return {"error": f"Ошибка custom_fields: {e}"}
            else:
                logging.error("custom_fields отсутствует в вебхуке")
                return {"error": "custom_fields отсутствует"}

        if not login:
            logging.error("Логин не передан в вебхуке")
            return {"error": "Логин не передан"}

        user = db.query(User).filter(User.login == login).first()
        if not user:
            logging.error(f"Пользователь {login} не найден для обработки вебхука")
            return {"error": "Пользователь не найден"}

        old_expiry = user.subscription_expires_at
        if user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow():
            user.subscription_expires_at += timedelta(days=30)
        else:
            user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)

        payment = Payment(
            invoice_id=invoice_id,
            user_login=login,
            amount=float(data.get("amount_crypto", 0)),
            status="success"
        )
        db.add(payment)
        db.commit()
        logging.info(f"Подписка продлена для {login} с {old_expiry} до {user.subscription_expires_at}, платёж {invoice_id} сохранён")

        if pending_invoice:
            db.delete(pending_invoice)
            db.commit()
            logging.info(f"PendingInvoice удалён для invoice_id: {invoice_id}")

        return {"ok": True}
    except SQLAlchemyError as e:
        db.rollback()
        logging.error(f"Ошибка базы данных в вебхуке: {e}")
        return {"error": f"Ошибка базы данных: {e}"}
    except Exception as e:
        logging.error(f"Общая ошибка вебхука: {e}")
        return {"error": str(e)}

@app.get("/pay")
async def redirect_to_payment(request: Request, db: Session = Depends(get_db)):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode("utf-8")
    except Exception as e:
        logging.error(f"Ошибка декодирования login из cookies для оплаты: {e}")
        login = None

    if not login:
        logging.info("Перенаправление на вход: логин отсутствует")
        return RedirectResponse(url="/login")

    logging.info(f"Перенаправление на оплату для {login}")
    invoice_url = await create_invoice(login, db)
    if invoice_url == "/payment-failed":
        logging.error(f"Не удалось создать инвойс для {login}")
        return templates.TemplateResponse("payment_failed.html", {"request": request, "error": "Не удалось создать инвойс"})
    return RedirectResponse(url=invoice_url)

@app.post("/reset-password")
async def reset_password(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    login = data.get("login")
    code = data.get("code")
    new_password = data.get("new_password")

    if not login or not code or not new_password:
        return JSONResponse({"error": "Недостаточно данных"}, status_code=400)

    reset = pending_password_resets.get(login)
    if not reset:
        return JSONResponse({"error": "Код не запрашивался"}, status_code=400)

    if reset["code"] != code or time.time() - reset["timestamp"] > 300:
        return JSONResponse({"error": "Неверный или просроченный код"}, status_code=403)

    user = db.query(User).filter(User.login == login).first()
    if not user:
        return JSONResponse({"error": "Пользователь не найден"}, status_code=404)

    user.password_hash = bcrypt.hash(new_password)
    db.commit()
    pending_password_resets.pop(login, None)

    logging.info(f"[PasswordReset] Пароль сброшен для {login}")
    return JSONResponse({"success": True})

@app.post("/confirm-reset-code")
async def confirm_reset_code(request: Request):
    data = await request.json()
    login = data.get("login")
    code = data.get("code")

    reset = pending_password_resets.get(login)
    if not reset:
        return JSONResponse({"error": "Код не запрашивался"}, status_code=400)

    if reset["code"] != code or time.time() - reset["timestamp"] > 300:
        return JSONResponse({"error": "Неверный или просроченный код"}, status_code=403)

    return JSONResponse({"success": True})

@app.post("/admin-confirm", response_class=HTMLResponse)
def confirm_admin_code(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    login_hex = request.cookies.get("login")
    try:
        login = bytes.fromhex(login_hex).decode('utf-8') if login_hex else None
    except Exception as e:
        logging.error(f"Ошибка декодирования login из cookies: {e}")
        login = None

    logging.info(f"Подтверждение кода админа для {login}, код: {code}")
    if not login or login not in pending_admin_actions:
        logging.error(f"Подтверждение отклонено для {login}: доступ запрещён или код не запрашивался")
        return templates.TemplateResponse("cod_TG.html", {
            "request": request,
            "error": "Доступ запрещён или код не запрашивался",
            "debug": {
                "remaining": "-"
            }
        })

    expected = pending_admin_actions.get(login)
    if expected["code"] != code or time.time() - expected["timestamp"] > 300:
        remaining = max(0, int(300 - (time.time() - expected["timestamp"])))
        logging.error(f"Подтверждение отклонено для {login}: неверный или просроченный код")
        return templates.TemplateResponse("cod_TG.html", {
            "request": request,
            "error": "Неверный или просроченный код",
            "debug": {
                "remaining": remaining
            }
        })

    logging.info(f"Код админа подтверждён для {login}")
    response = RedirectResponse(url="/lichny_kabinet", status_code=303)
    response.set_cookie(key="is_admin", value="True", httponly=True, secure=True, samesite="strict")
    return response