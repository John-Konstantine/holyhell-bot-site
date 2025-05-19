from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from datetime import datetime
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Загружаем переменные из .env
load_dotenv()
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise ValueError("FERNET_KEY не найден в .env")
fernet = Fernet(FERNET_KEY.encode())

# База
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    login = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    api_key = Column(String, nullable=False)  # Здесь ключ Binance
    api_secret_encrypted = Column(String, nullable=False)  # Здесь зашифрованный ключ Binance
    telegram_id = Column(String, nullable=False)
    telegram_token_encrypted = Column(String, nullable=False)
    hwid = Column(String, nullable=True)
    subscription_expires_at = Column(DateTime, nullable=True)

    def decrypt_api_secret(self):
        return fernet.decrypt(self.api_secret_encrypted.encode()).decode()

    def decrypt_telegram_token(self):
        return fernet.decrypt(self.telegram_token_encrypted.encode()).decode()

class AdminLog(Base):
    __tablename__ = "admin_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_login = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target_login = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(String, unique=True, index=True)
    user_login = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class PendingInvoice(Base):
    __tablename__ = "pending_invoices"
    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(String, unique=True, index=True)
    user_login = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Подключение к PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL не найден в .env")
print("DATABASE_URL:", DATABASE_URL)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,       # проверяет «живость» соединения перед использованием
    pool_recycle=300          # разрывает и восстанавливает соединения раз в 5 минут
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

if __name__ == "__main__":
    print("Создаём таблицы...")
    Base.metadata.create_all(bind=engine)
    print("Таблицы созданы")