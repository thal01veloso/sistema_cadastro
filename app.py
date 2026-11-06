import os
import secrets
from flask import Flask, flash, redirect, render_template, request, send_from_directory, session, url_for
from config import Config
from database import get_csrf_token, mysql
from routes import auth_bp, clientes_bp, cobrancas_bp


def create_app(config_class=Config):
    """Application Factory do ClientSys."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.secret_key = app.config['SECRET_KEY']

    # Garante a criação da pasta de uploads
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Inicializa extensão MySQL
    mysql.init_app(app)

    # Registra helper global de CSRF no Jinja2
    app.jinja_env.globals['csrf_token'] = get_csrf_token

    # Proteção global contra CSRF em requisições POST
    @app.before_request
    def csrf_protect():
        if request.method == 'POST':
            token = session.get('_csrf_token')
            form_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
            if not token or not form_token or not secrets.compare_digest(str(token), str(form_token)):
                flash('Sessão expirada ou token de segurança inválido. Tente novamente.', 'danger')
                return redirect(request.referrer or url_for('login'))

    # Registra Blueprints mantendo nomes curtos de endpoints para compatibilidade com templates
    for bp in (auth_bp, clientes_bp, cobrancas_bp):
        app.register_blueprint(bp)

    # Mapeia aliases sem prefixo do blueprint (ex: url_for('login') oltre de url_for('auth.login'))
    for rule in list(app.url_map.iter_rules()):
        if '.' in rule.endpoint and rule.endpoint != 'static':
            short_endpoint = rule.endpoint.split('.', 1)[1]
            if short_endpoint not in app.view_functions:
                app.add_url_rule(
                    rule.rule,
                    endpoint=short_endpoint,
                    view_func=app.view_functions[rule.endpoint],
                    methods=rule.methods
                )

    # Error handlers e rotas estáticas auxiliares
    @app.errorhandler(404)
    def page_not_found(e):
        try:
            return render_template('404.html'), 404
        except Exception:
            return "Página não encontrada", 404

    @app.errorhandler(500)
    def internal_server_error(e):
        try:
            return render_template('500.html'), 500
        except Exception:
            return "Erro interno do servidor", 500

    @app.route('/favicon.ico')
    def favicon():
        favicon_path = os.path.join(app.root_path, 'static', 'favicon.ico')
        if os.path.isfile(favicon_path):
            return send_from_directory(
                os.path.join(app.root_path, 'static'),
                'favicon.ico',
                mimetype='image/vnd.microsoft.icon'
            )
        return '', 204

    @app.cli.command('init-db')
    def init_db_command():
        """Inicializa as tabelas do banco de dados a partir do schema.txt."""
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.txt')
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()
        with mysql.connection.cursor() as cur:
            for statement in sql_script.split(';'):
                stmt = statement.strip()
                if stmt:
                    cur.execute(stmt)
            mysql.connection.commit()
        print('Banco de dados inicializado com sucesso!')

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')
