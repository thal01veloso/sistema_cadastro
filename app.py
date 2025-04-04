from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os
import logging

# Configuração inicial
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def db_query(query, params=None, fetchone=False):
    """Executa consultas no banco de dados de forma segura"""
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
    """Executa operações de escrita no banco de dados"""
    try:
        with mysql.connection.cursor() as cur:
            cur.execute(query, params or ())
            mysql.connection.commit()
            return cur.lastrowid
    except Exception as e:
        logger.error(f"Database commit error: {e}")
        mysql.connection.rollback()
        raise

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = db_query(
            "SELECT * FROM usuarios WHERE username = %s", 
            (username,), 
            fetchone=True
        )

        if user and check_password_hash(user['password'], password):
            session.update({
                'logged_in': True,
                'username': user['username'],
                'nome': user['nome']
            })
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('listar_clientes'))
        
        flash('Usuário ou senha incorretos!', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi deslogado com sucesso.', 'info')
    return redirect(url_for('login'))

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        form_data = {
            'nome': request.form.get('nome', '').strip(),
            'username': request.form.get('username', '').strip(),
            'password': request.form.get('password', ''),
            'confirm_password': request.form.get('confirm_password', '')
        }

        # Validações
        if not all(form_data.values()):
            flash('Todos os campos são obrigatórios!', 'danger')
            return redirect(url_for('registrar'))

        if len(form_data['username']) < 4:
            flash('Nome de usuário deve ter pelo menos 4 caracteres', 'danger')
            return redirect(url_for('registrar'))

        if form_data['password'] != form_data['confirm_password']:
            flash('As senhas não coincidem!', 'danger')
            return redirect(url_for('registrar'))

        if len(form_data['password']) < 8:
            flash('A senha deve ter no mínimo 8 caracteres', 'danger')
            return redirect(url_for('registrar'))

        # Verifica se usuário existe
        if db_query("SELECT id FROM usuarios WHERE username = %s", 
                   (form_data['username'],), fetchone=True):
            flash('Nome de usuário já está em uso. Escolha outro.', 'danger')
            return redirect(url_for('registrar'))

        # Cria novo usuário
        try:
            db_commit(
                "INSERT INTO usuarios (nome, username, password) VALUES (%s, %s, %s)",
                (form_data['nome'], form_data['username'], 
                 generate_password_hash(form_data['password'], method='pbkdf2:sha256'))
            )
            flash('Registro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Erro ao registrar: {str(e)}', 'danger')
            return redirect(url_for('registrar'))

    return render_template('registrar.html')

# Rotas principais
@app.route('/')
@login_required
def index():
    return redirect(url_for('listar_clientes'))

@app.route('/cadastrar_clientes', methods=['GET', 'POST'])
@login_required
def cadastrar_clientes():
    if request.method == 'POST':
        try:
            db_commit(
                "INSERT INTO clientes (nome, email, telefone) VALUES (%s, %s, %s)",
                (request.form['nome'], request.form['email'], request.form['telefone'])
            )
            flash('Cliente cadastrado com sucesso!', 'success')
            return redirect(url_for('listar_clientes'))
        except Exception as e:
            flash(f'Erro ao cadastrar cliente: {str(e)}', 'danger')
            return redirect(url_for('cadastrar_clientes'))

    return render_template('cadastrar.html')

@app.route('/listar_clientes')
@login_required
def listar_clientes():
    clientes = db_query("SELECT * FROM clientes")
    return render_template('listar.html', clientes=clientes)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')