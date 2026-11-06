import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_WHATSAPP_TEMPLATE = (
    "*Cobrança - {nome}*\n\n"
    "💰 *Valor:* R$ {valor}\n"
    "📅 *Vencimento:* {data_agendamento}\n"
    "📝 *Descrição:* {descricao}\n\n"
    "🔑 *Chave PIX:* {chave_pix}\n\n"
    "Por favor, efetue o pagamento o mais breve possível.\n"
    "Agradecemos pela compreensão!"
)


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.getenv('MYSQL_USER')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
    MYSQL_DB = os.getenv('MYSQL_DB')
    MYSQL_CURSORCLASS = 'DictCursor'
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB
