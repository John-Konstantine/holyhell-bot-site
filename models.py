from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from datetime import datetime
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Загружаем ключ из .env
load_dotenv()
FERNET_KEY = os.getenv("FERNET_KEY")
fernet = Fernet(FERNET_KEY.encode())

# База
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    login = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    api_key = Column(String, nullable=False)
    api_secret_encrypted = Column(String, nullable=False)
    telegram_token_encrypted = Column(String, nullable=False)
    telegram_id = Column(String, nullable=False)
    hwid = Column(String, nullable=True)
    subscription_expires_at = Column(DateTime, default=datetime.utcnow)

    def decrypt_api_secret(self):
        return fernet.decrypt(self.api_secret_encrypted.encode()).decode()

    def decrypt_telegram_token(self):
        return fernet.decrypt(self.telegram_token_encrypted.encode()).decode()
    
class AdminLog(Base):
    __tablename__ = "admin_log"

    id = Column(Integer, primary_key=True, index=True)
    admin_login = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target_login = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


# Подключение к PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL:", DATABASE_URL)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

if __name__ == "__main__":
    print("Создаём таблицы...")
    Base.metadata.create_all(bind=engine)
