from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory  # Adicione send_from_directory
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
import logging
import os
from datetime import datetime

# Configuração inicial
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB



if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


mysql = MySQL(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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
            "SELECT id, username, password, nome FROM usuarios WHERE username = %s", 
            (username,), 
            fetchone=True
        )

        if user and check_password_hash(user['password'], password):
            session.update({
                'logged_in': True,
                'user_id': user['id'],  # Garanta que isso está sendo salvo
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
            # Processar upload da foto (mantido igual)
            foto = None
            if 'foto' in request.files:
                file = request.files['foto']
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    foto = filename

            # Adiciona o ID do usuário logado
            db_commit(
                "INSERT INTO clientes (nome, email, telefone, foto, usuario_id) VALUES (%s, %s, %s, %s, %s)",
                (request.form['nome'], request.form['email'], request.form['telefone'], foto, session['user_id'])
            )
            flash('Cliente cadastrado com sucesso!', 'success')
            return redirect(url_for('listar_clientes'))
            
        except Exception as e:
            flash(f'Erro ao cadastrar cliente: {str(e)}', 'danger')
            return redirect(url_for('cadastrar_clientes'))
    
    return render_template('cadastrar.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        # Se o arquivo não existir, retorna o ícone padrão
        return redirect(url_for('static', filename='img/default-user.png'))

@app.route('/listar_clientes')
@login_required
def listar_clientes():
    clientes = db_query(
        "SELECT * FROM clientes WHERE usuario_id = %s ORDER BY nome ASC",
        (session['user_id'],)
    )
    return render_template('listar.html', clientes=clientes)
   

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template('404.html'), 404
    except:
        return "Página não encontrada", 404

@app.errorhandler(500)
def internal_server_error(e):
    try:
        return render_template('500.html'), 500
    except:
        return "Erro interno do servidor", 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                              'favicon.ico', mimetype='image/vnd.microsoft.icon')
@app.route('/excluir_cliente/<int:id>', methods=['POST'])
@login_required
def excluir_cliente(id):
    try:
        # Primeiro obtém o nome do arquivo da foto se existir
        cliente = db_query(
            "SELECT foto FROM clientes WHERE id = %s AND usuario_id = %s",
            (id, session['user_id']),
            fetchone=True
        )
        
        # Exclui o cliente do banco de dados
        db_commit(
            "DELETE FROM clientes WHERE id = %s AND usuario_id = %s",
            (id,session['user_id'])
        )
        
        # Se existia uma foto, exclui do sistema de arquivos
        if cliente and cliente['foto']:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], cliente['foto']))
            except OSError as e:
                logger.error(f"Erro ao excluir foto: {e}")
        
        flash('Cliente excluído com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao excluir cliente: {str(e)}', 'danger')
    
    return redirect(url_for('listar_clientes'))


@app.route('/editar_cliente/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_cliente(id):
    if request.method == 'GET':
        # Busca os dados atuais do cliente
        cliente = db_query(
        "SELECT * FROM clientes WHERE id = %s AND usuario_id = %s",
        (id, session['user_id']),
        fetchone=True
    )
        if not cliente:
            flash('Cliente não encontrado!', 'danger')
            return redirect(url_for('listar_clientes'))
        
        return render_template('editar.html', cliente=cliente)
    
    elif request.method == 'POST':
        try:
            # Processa os dados do formulário
            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip()
            telefone = request.form.get('telefone', '').strip()
            
            # Processa o upload da nova foto (se fornecida)
            nova_foto = None
            if 'foto' in request.files:
                file = request.files['foto']
                if file and file.filename != '' and allowed_file(file.filename):
                    # Remove a foto antiga se existir
                    cliente_atual = db_query(
                        "SELECT foto FROM clientes WHERE id = %s",
                        (id,),
                        fetchone=True
                    )
                    if cliente_atual and cliente_atual['foto']:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], cliente_atual['foto']))
                        except OSError as e:
                            logger.error(f"Erro ao excluir foto antiga: {e}")
                    
                    # Salva a nova foto
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    nova_foto = filename
            
            # Atualiza no banco de dados
            if nova_foto:
                db_commit(
                    "UPDATE clientes SET nome = %s, email = %s, telefone = %s, foto = %s WHERE id = %s",
                    (nome, email, telefone, nova_foto, id)
                )
            else:
                db_commit(
                    "UPDATE clientes SET nome = %s, email = %s, telefone = %s WHERE id = %s",
                    (nome, email, telefone, id)
                )
            
            flash('Cliente atualizado com sucesso!', 'success')
            return redirect(url_for('listar_clientes'))
        
        except Exception as e:
            flash(f'Erro ao atualizar cliente: {str(e)}', 'danger')
            return redirect(url_for('editar_cliente', id=id))

@app.route('/buscar_clientes')
@login_required
def buscar_clientes():
    nome = request.args.get('nome', '').strip()
    
    if nome:
        clientes = db_query(
            "SELECT * FROM clientes WHERE nome LIKE %s AND usuario_id = %s ORDER BY nome",
            (f"%{nome}%", session['user_id'])
        )
    else:
        clientes = db_query(
            "SELECT * FROM clientes WHERE usuario_id = %s ORDER BY nome",
            (session['user_id'],)
        )
    
    return render_template('_clientes_partial.html', clientes=clientes)
    
@app.route('/agendar_cobranca/<int:cliente_id>')
@login_required
def agendar_cobranca(cliente_id):
    # Obter cliente
    cliente = db_query(
        "SELECT * FROM clientes WHERE id = %s",
        (cliente_id,),
        fetchone=True
    )
    
    if not cliente:
        flash('Cliente não encontrado!', 'danger')
        return redirect(url_for('listar_clientes'))

    # Obter cobranças existentes
    query = """
        SELECT id, cliente_id, valor, 
               descricao, 
               data_agendamento,
               DATE_FORMAT(data_agendamento, '%%d/%%m/%%Y %%H:%%i') as data_formatada,
               status
        FROM cobrancas 
        WHERE cliente_id = %s
        ORDER BY data_agendamento DESC
    """
    cobrancas = db_query(query, (cliente_id,))
    
    # --- CÓDIGO DE PROCESSAMENTO DO FORMULÁRIO ---
    if request.method == 'POST':
        try:
            valor = request.form.get('valor', '').strip()
            descricao = request.form.get('descricao', '').strip()
            data_agendamento = request.form.get('data_agendamento', '').strip()
            
            if not all([valor, data_agendamento]):
                flash('Valor e data são obrigatórios!', 'danger')
                return redirect(url_for('agendar_cobranca', cliente_id=cliente_id))
            
            try:
                valor_float = float(valor)
                data_obj = datetime.strptime(data_agendamento, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Formato inválido para valor ou data!', 'danger')
                return redirect(url_for('agendar_cobranca', cliente_id=cliente_id))
            
            db_commit(
                "INSERT INTO cobrancas (cliente_id, valor, descricao, data_agendamento) VALUES (%s, %s, %s, %s)",
                (cliente_id, valor_float, descricao, data_obj)
            )
            
            flash('Cobrança agendada com sucesso!', 'success')
            return redirect(url_for('agendar_cobranca', cliente_id=cliente_id))
            
        except Exception as e:
            flash(f'Erro ao agendar cobrança: {str(e)}', 'danger')
            return redirect(url_for('agendar_cobranca', cliente_id=cliente_id))
    # --- FIM DO CÓDIGO DE PROCESSAMENTO ---
    
    return render_template('agendar_cobranca.html', 
                         cliente=cliente, 
                         cobrancas=cobrancas)


@app.route('/enviar_cobranca/<int:cobranca_id>')
@login_required
def enviar_cobranca(cobranca_id):
    try:
        # Consulta otimizada com tratamento de dados
        cobranca = db_query(
            """SELECT c.id, c.valor, c.descricao, c.status,
                      cl.nome, cl.telefone, cl.id as cliente_id
               FROM cobrancas c
               JOIN clientes cl ON c.cliente_id = cl.id
               WHERE c.id = %s""",
            (cobranca_id,),
            fetchone=True
        )
        
        if not cobranca:
            flash('Cobrança não encontrada!', 'danger')
            return redirect(url_for('listar_cobrancas'))
        
        # Validação do telefone
        telefone = cobranca['telefone']
        if not telefone:
            flash('Cliente não possui telefone cadastrado!', 'danger')
            return redirect(url_for('listar_cobrancas'))
            
        # Formatação do telefone
        telefone = ''.join(filter(str.isdigit, str(telefone)))
        if len(telefone) < 11:
            flash('Número de telefone inválido!', 'danger')
            return redirect(url_for('listar_cobrancas'))
            
        # Adiciona código do Brasil se necessário
        if not telefone.startswith('55') and len(telefone) <= 11:
            telefone = '55' + telefone.lstrip('0')

        # Formatação da mensagem
        mensagem = (
            f"*Cobrança - {cobranca['nome']}*\n\n"
            f"💰 *Valor:* R$ {float(cobranca['valor']):.2f}\n"
        )
        
        if cobranca['descricao']:
            mensagem += f"📝 *Descrição:* {cobranca['descricao']}\n\n"
        
        mensagem += (
            "Por favor, efetue o pagamento o mais breve possível.\n"
            "Agradecemos pela compreensão!"
        )

        # Codificação da mensagem
        from urllib.parse import quote
        mensagem_codificada = quote(mensagem)
        
        # Geração do link
        whatsapp_url = f"https://wa.me/{telefone}?text={mensagem_codificada}"
        
        # Atualização do status
        db_commit(
            "UPDATE cobrancas SET status = 'enviada', data_envio = NOW() WHERE id = %s",
            (cobranca_id,)
        )
        
        # Debug
        logger.info(f"Enviando cobrança para {telefone}: {mensagem}")
        
        return redirect(whatsapp_url)
        
    except Exception as e:
        logger.error(f"Erro ao enviar cobrança: {str(e)}", exc_info=True)
        flash(f'Erro ao enviar cobrança: {str(e)}', 'danger')
        return redirect(url_for('listar_cobrancas'))


@app.route('/listar_cobrancas')
@login_required
def listar_cobrancas():
    # Filtra cobranças apenas dos clientes do usuário
    query = """
        SELECT c.id, c.valor, c.descricao, c.status,
               DATE_FORMAT(c.data_agendamento, '%%d/%%m/%%Y %%H:%%i') as data_formatada,
               cl.nome as cliente_nome, 
               cl.id as cliente_id,
               cl.telefone
        FROM cobrancas c
        JOIN clientes cl ON c.cliente_id = cl.id
        WHERE cl.usuario_id = %s
        ORDER BY c.data_agendamento DESC
    """
    cobrancas = db_query(query, (session['user_id'],))
    return render_template('listar_cobrancas.html', cobrancas=cobrancas)

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')