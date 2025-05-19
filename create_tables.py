# create_tables.py

from sqlalchemy import create_engine
from models import Base  # Импортируем Base из файла с моделями
import os
from dotenv import load_dotenv

# Загружаем ключи из .env
load_dotenv()

# Подключаемся к базе данных
DATABASE_URL = os.getenv("DATABASE_URL")  # Получаем URL из .env
engine = create_engine(DATABASE_URL)

# Создаём таблицы
Base.metadata.create_all(bind=engine)

print("Таблицы успешно созданы!")
