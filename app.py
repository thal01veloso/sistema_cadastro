from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os

app = Flask(__name__)

# Configuração do MySQL
load_dotenv()
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Configuração da chave secreta - ESSENCIAL PARA SESSÕES
app.secret_key = os.getenv('SECRET_KEY') or os.urandom(24)  
mysql = MySQL(app)

# Decorator corrigido com wraps
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            session['nome'] = user['nome']
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('listar_clientes'))
        else:
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
        nome = request.form.get('nome', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validação básica
        if not all([nome, username, password, confirm_password]):
            flash('Todos os campos são obrigatórios!', 'danger')
            return redirect(url_for('registrar_clientes'))
        
        if len(username) < 4:
            flash('Nome de usuário deve ter pelo menos 4 caracteres', 'danger')
            return redirect(url_for('registrar_clientes'))
        
        if password != confirm_password:
            flash('As senhas não coincidem!', 'danger')
            return redirect(url_for('registrar_clientes'))
        
        if len(password) < 8:
            flash('A senha deve ter no mínimo 8 caracteres', 'danger')
            return redirect(url_for('registrar_clientes'))
        
        cur = mysql.connection.cursor()
        try:
            # Verifica se o usuário já existe
            cur.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
            if cur.fetchone():
                flash('Nome de usuário já está em uso. Escolha outro.', 'danger')
                return redirect(url_for('registrar_cliente'))
            
            # Gera o hash da senha
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            
            # Insere o novo usuário
            cur.execute(
                "INSERT INTO usuarios (nome, username, password) VALUES (%s, %s, %s)",
                (nome, username, password_hash)
            )
            mysql.connection.commit()
            flash('Registro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Erro ao registrar: {str(e)}', 'danger')
            return redirect(url_for('registrar_clientes'))
        finally:
            cur.close()
    
    return render_template('registrar.html')
# Rotas principais
@app.route('/')
@login_required
def index():
    return redirect(url_for('listar_clientes'))

@app.route('/cadastrar_clientes', methods=['GET', 'POST'])  # Corrigi o nome da rota (estava 'cadastran')
@login_required
def cadastrar_clientes():  # Mudei o nome da função para evitar conflito
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        telefone = request.form['telefone']
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO clientes (nome, email, telefone) VALUES (%s, %s, %s)", 
                   (nome, email, telefone))
        mysql.connection.commit()
        cur.close()
        
        flash('Cliente cadastrado com sucesso!', 'success')
        return redirect(url_for('listar_clientes'))
    
    return render_template('cadastrar.html')

@app.route('/listar_clientes')
@login_required
def listar_clientes():  # Mudei o nome da função para evitar conflito
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM clientes")
    clientes = cur.fetchall()
    cur.close()
    return render_template('listar.html', clientes=clientes)

if __name__ == '__main__':
    app.run(debug=True)