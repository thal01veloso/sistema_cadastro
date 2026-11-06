import logging
import secrets
from functools import wraps
from flask import current_app, flash, redirect, request, session, url_for
from flask_mysqldb import MySQL

mysql = MySQL()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def allowed_file(filename):
    allowed = current_app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif'})
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def get_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def db_query(query, params=None, fetchone=False):
    """Executa consultas no banco de dados de forma segura."""
    try:
        with mysql.connection.cursor() as cur:
            cur.execute(query, params or ())
            if fetchone:
                return cur.fetchone()
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Database error: {e}")
        mysql.connection.rollback()
        raise


def db_commit(query, params=None):
    """Executa operações de escrita no banco de dados."""
    try:
        with mysql.connection.cursor() as cur:
            cur.execute(query, params or ())
            mysql.connection.commit()
            return cur.lastrowid
    except Exception as e:
        logger.error(f"Database commit error: {e}")
        mysql.connection.rollback()
        raise
