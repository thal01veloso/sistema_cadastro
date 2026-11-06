from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from config import DEFAULT_WHATSAPP_TEMPLATE
from database import db_commit, db_query, login_required

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'], endpoint='login')
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
                'user_id': user['id'],
                'username': user['username'],
                'nome': user['nome']
            })
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))

        flash('Usuário ou senha incorretos!', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout', endpoint='logout')
def logout():
    session.clear()
    flash('Você foi deslogado com sucesso.', 'info')
    return redirect(url_for('login'))


@auth_bp.route('/registrar', methods=['GET', 'POST'], endpoint='registrar')
def registrar():
    if request.method == 'POST':
        form_data = {
            'nome': request.form.get('nome', '').strip(),
            'username': request.form.get('username', '').strip(),
            'password': request.form.get('password', ''),
            'confirm_password': request.form.get('confirm_password', '')
        }

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

        if db_query("SELECT id FROM usuarios WHERE username = %s", (form_data['username'],), fetchone=True):
            flash('Nome de usuário já está em uso. Escolha outro.', 'danger')
            return redirect(url_for('registrar'))

        try:
            db_commit(
                "INSERT INTO usuarios (nome, username, password) VALUES (%s, %s, %s)",
                (
                    form_data['nome'],
                    form_data['username'],
                    generate_password_hash(form_data['password'], method='pbkdf2:sha256')
                )
            )
            flash('Registro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Erro ao registrar: {str(e)}', 'danger')
            return redirect(url_for('registrar'))

    return render_template('registrar.html')


@auth_bp.route('/perfil', methods=['GET', 'POST'], endpoint='perfil')
@login_required
def perfil():
    user_id = session['user_id']
    usuario = db_query(
        "SELECT * FROM usuarios WHERE id = %s",
        (user_id,),
        fetchone=True
    )

    if request.method == 'POST':
        acao = request.form.get('acao', 'dados')

        if acao == 'dados':
            novo_nome = request.form.get('nome', '').strip()
            if not novo_nome:
                flash('O nome não pode ficar vazio!', 'danger')
                return redirect(url_for('perfil'))

            try:
                db_commit(
                    "UPDATE usuarios SET nome = %s WHERE id = %s",
                    (novo_nome, user_id)
                )
                session['nome'] = novo_nome
                flash('Dados do perfil atualizados com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao atualizar perfil: {str(e)}', 'danger')

        elif acao == 'whatsapp':
            chave_pix = request.form.get('chave_pix', '').strip()
            template_whatsapp = request.form.get('template_whatsapp', '').strip() or DEFAULT_WHATSAPP_TEMPLATE
            session['chave_pix'] = chave_pix
            session['template_whatsapp'] = template_whatsapp
            try:
                db_commit(
                    "UPDATE usuarios SET chave_pix = %s, template_whatsapp = %s WHERE id = %s",
                    (chave_pix, template_whatsapp, user_id)
                )
            except Exception:
                pass
            flash('Modelo de mensagem do WhatsApp e Chave PIX salvos com sucesso!', 'success')

        elif acao == 'senha':
            senha_atual = request.form.get('senha_atual', '')
            nova_senha = request.form.get('nova_senha', '')
            confirmar_senha = request.form.get('confirmar_senha', '')

            if not check_password_hash(usuario['password'], senha_atual):
                flash('A senha atual informada está incorreta!', 'danger')
                return redirect(url_for('perfil'))

            if len(nova_senha) < 8:
                flash('A nova senha deve ter no mínimo 8 caracteres!', 'danger')
                return redirect(url_for('perfil'))

            if nova_senha != confirmar_senha:
                flash('A confirmação da nova senha não coincide!', 'danger')
                return redirect(url_for('perfil'))

            try:
                novo_hash = generate_password_hash(nova_senha, method='pbkdf2:sha256')
                db_commit(
                    "UPDATE usuarios SET password = %s WHERE id = %s",
                    (novo_hash, user_id)
                )
                flash('Senha alterada com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao alterar senha: {str(e)}', 'danger')

        return redirect(url_for('perfil'))

    template_atual = (
        usuario.get('template_whatsapp')
        or session.get('template_whatsapp')
        or DEFAULT_WHATSAPP_TEMPLATE
    )
    chave_pix_atual = usuario.get('chave_pix') or session.get('chave_pix') or ''

    return render_template(
        'perfil.html',
        usuario=usuario,
        template_whatsapp=template_atual,
        chave_pix=chave_pix_atual
    )
