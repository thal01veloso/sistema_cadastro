import csv
import io
import os
import uuid
from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename
from database import allowed_file, db_commit, db_query, logger, login_required

clientes_bp = Blueprint('clientes', __name__)


@clientes_bp.route('/', endpoint='index')
@login_required
def index():
    return redirect(url_for('dashboard'))


@clientes_bp.route('/dashboard', endpoint='dashboard')
@login_required
def dashboard():
    user_id = session['user_id']

    clientes_kpi = db_query(
        """SELECT 
            COUNT(*) AS total_clientes,
            SUM(CASE WHEN telefone IS NOT NULL AND TRIM(telefone) != '' THEN 1 ELSE 0 END) AS clientes_com_telefone
           FROM clientes
           WHERE usuario_id = %s""",
        (user_id,),
        fetchone=True
    ) or {'total_clientes': 0, 'clientes_com_telefone': 0}

    cobrancas_kpi = db_query(
        """SELECT
            COUNT(*) AS total_cobrancas,
            COALESCE(SUM(valor), 0) AS valor_total,
            SUM(CASE WHEN status = 'pendente' THEN 1 ELSE 0 END) AS qtd_pendentes,
            COALESCE(SUM(CASE WHEN status = 'pendente' THEN valor ELSE 0 END), 0) AS valor_pendente,
            SUM(CASE WHEN status IN ('enviada', 'paga') THEN 1 ELSE 0 END) AS qtd_enviadas,
            COALESCE(SUM(CASE WHEN status IN ('enviada', 'paga') THEN valor ELSE 0 END), 0) AS valor_enviado,
            SUM(CASE WHEN status = 'pendente' AND data_agendamento < NOW() THEN 1 ELSE 0 END) AS qtd_atrasadas,
            COALESCE(SUM(CASE WHEN status = 'pendente' AND data_agendamento < NOW() THEN valor ELSE 0 END), 0) AS valor_atrasado,
            SUM(CASE WHEN status = 'pendente' AND DATE(data_agendamento) = CURDATE() THEN 1 ELSE 0 END) AS qtd_hoje,
            COALESCE(SUM(CASE WHEN status = 'pendente' AND DATE(data_agendamento) = CURDATE() THEN valor ELSE 0 END), 0) AS valor_hoje
           FROM cobrancas c
           JOIN clientes cl ON c.cliente_id = cl.id
           WHERE cl.usuario_id = %s""",
        (user_id,),
        fetchone=True
    ) or {}

    proximas_cobrancas = db_query(
        """SELECT c.id, c.valor, c.descricao, c.status,
                  DATE_FORMAT(c.data_agendamento, '%%d/%%m/%%Y %%H:%%i') AS data_formatada,
                  (c.data_agendamento < NOW()) AS atrasada,
                  cl.nome AS cliente_nome, cl.id AS cliente_id, cl.telefone
           FROM cobrancas c
           JOIN clientes cl ON c.cliente_id = cl.id
           WHERE cl.usuario_id = %s AND c.status = 'pendente'
           ORDER BY c.data_agendamento ASC
           LIMIT 5""",
        (user_id,)
    )

    top_clientes = db_query(
        """SELECT cl.id, cl.nome, cl.email, cl.foto,
                  COUNT(c.id) AS qtd_cobrancas,
                  COALESCE(SUM(c.valor), 0) AS total_valor,
                  COALESCE(SUM(CASE WHEN c.status = 'pendente' THEN c.valor ELSE 0 END), 0) AS valor_pendente
           FROM clientes cl
           LEFT JOIN cobrancas c ON c.cliente_id = cl.id
           WHERE cl.usuario_id = %s
           GROUP BY cl.id, cl.nome, cl.email, cl.foto
           ORDER BY total_valor DESC, cl.nome ASC
           LIMIT 5""",
        (user_id,)
    )

    total_cobrancas = int(cobrancas_kpi.get('total_cobrancas') or 0)
    qtd_enviadas = int(cobrancas_kpi.get('qtd_enviadas') or 0)
    taxa_envio = round((qtd_enviadas / total_cobrancas) * 100, 1) if total_cobrancas > 0 else 0.0

    kpis = {
        'total_clientes': int(clientes_kpi.get('total_clientes') or 0),
        'clientes_com_telefone': int(clientes_kpi.get('clientes_com_telefone') or 0),
        'total_cobrancas': total_cobrancas,
        'valor_total': float(cobrancas_kpi.get('valor_total') or 0),
        'qtd_pendentes': int(cobrancas_kpi.get('qtd_pendentes') or 0),
        'valor_pendente': float(cobrancas_kpi.get('valor_pendente') or 0),
        'qtd_enviadas': qtd_enviadas,
        'valor_enviado': float(cobrancas_kpi.get('valor_enviado') or 0),
        'qtd_atrasadas': int(cobrancas_kpi.get('qtd_atrasadas') or 0),
        'valor_atrasado': float(cobrancas_kpi.get('valor_atrasado') or 0),
        'qtd_hoje': int(cobrancas_kpi.get('qtd_hoje') or 0),
        'valor_hoje': float(cobrancas_kpi.get('valor_hoje') or 0),
        'taxa_envio': taxa_envio
    }

    return render_template(
        'dashboard.html',
        kpis=kpis,
        proximas_cobrancas=proximas_cobrancas,
        top_clientes=top_clientes
    )


@clientes_bp.route('/cadastrar_clientes', methods=['GET', 'POST'], endpoint='cadastrar_clientes')
@login_required
def cadastrar_clientes():
    if request.method == 'POST':
        try:
            foto = None
            if 'foto' in request.files:
                file = request.files['foto']
                if file and file.filename != '' and allowed_file(file.filename):
                    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
                    filename = f"{uuid.uuid4().hex}{ext}"
                    file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
                    foto = filename

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


@clientes_bp.route('/uploads/<filename>', endpoint='uploaded_file')
@login_required
def uploaded_file(filename):
    safe_name = secure_filename(filename)
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_name)
    if os.path.isfile(file_path):
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], safe_name)
    return '', 404


@clientes_bp.route('/listar_clientes', endpoint='listar_clientes')
@login_required
def listar_clientes():
    clientes = db_query(
        "SELECT * FROM clientes WHERE usuario_id = %s ORDER BY nome ASC",
        (session['user_id'],)
    )
    return render_template('listar.html', clientes=clientes)


@clientes_bp.route('/cliente/<int:id>', endpoint='detalhes_cliente')
@login_required
def detalhes_cliente(id):
    cliente = db_query(
        "SELECT * FROM clientes WHERE id = %s AND usuario_id = %s",
        (id, session['user_id']),
        fetchone=True
    )
    if not cliente:
        flash('Cliente não encontrado!', 'danger')
        return redirect(url_for('listar_clientes'))

    cobrancas = db_query(
        """SELECT id, valor, descricao, status,
                  DATE_FORMAT(data_agendamento, '%%d/%%m/%%Y %%H:%%i') as data_formatada,
                  DATE_FORMAT(data_envio, '%%d/%%m/%%Y %%H:%%i') as envio_formatado
           FROM cobrancas
           WHERE cliente_id = %s AND usuario_id = %s
           ORDER BY data_agendamento DESC""",
        (id, session['user_id'])
    )

    resumo = db_query(
        """SELECT
            COUNT(*) AS total_cobrancas,
            COALESCE(SUM(valor), 0) AS valor_total,
            COALESCE(SUM(CASE WHEN status = 'pendente' THEN valor ELSE 0 END), 0) AS valor_pendente,
            COALESCE(SUM(CASE WHEN status IN ('enviada', 'paga') THEN valor ELSE 0 END), 0) AS valor_enviado
           FROM cobrancas
           WHERE cliente_id = %s AND usuario_id = %s""",
        (id, session['user_id']),
        fetchone=True
    ) or {'total_cobrancas': 0, 'valor_total': 0, 'valor_pendente': 0, 'valor_enviado': 0}

    return render_template('detalhes.html', cliente=cliente, cobrancas=cobrancas, resumo=resumo)


@clientes_bp.route('/excluir_cliente/<int:id>', methods=['POST'], endpoint='excluir_cliente')
@login_required
def excluir_cliente(id):
    try:
        cliente = db_query(
            "SELECT foto FROM clientes WHERE id = %s AND usuario_id = %s",
            (id, session['user_id']),
            fetchone=True
        )

        db_commit(
            "DELETE FROM clientes WHERE id = %s AND usuario_id = %s",
            (id, session['user_id'])
        )

        if cliente and cliente['foto']:
            try:
                os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], cliente['foto']))
            except OSError as e:
                logger.error(f"Erro ao excluir foto: {e}")

        flash('Cliente excluído com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao excluir cliente: {str(e)}', 'danger')

    return redirect(url_for('listar_clientes'))


@clientes_bp.route('/editar_cliente/<int:id>', methods=['GET', 'POST'], endpoint='editar_cliente')
@login_required
def editar_cliente(id):
    if request.method == 'GET':
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
            cliente_atual = db_query(
                "SELECT id, foto FROM clientes WHERE id = %s AND usuario_id = %s",
                (id, session['user_id']),
                fetchone=True
            )
            if not cliente_atual:
                flash('Cliente não encontrado ou permissão negada!', 'danger')
                return redirect(url_for('listar_clientes'))

            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip()
            telefone = request.form.get('telefone', '').strip()

            nova_foto = None
            if 'foto' in request.files:
                file = request.files['foto']
                if file and file.filename != '' and allowed_file(file.filename):
                    if cliente_atual['foto']:
                        try:
                            os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], cliente_atual['foto']))
                        except OSError as e:
                            logger.error(f"Erro ao excluir foto antiga: {e}")

                    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
                    filename = f"{uuid.uuid4().hex}{ext}"
                    file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
                    nova_foto = filename

            if nova_foto:
                db_commit(
                    "UPDATE clientes SET nome = %s, email = %s, telefone = %s, foto = %s WHERE id = %s AND usuario_id = %s",
                    (nome, email, telefone, nova_foto, id, session['user_id'])
                )
            else:
                db_commit(
                    "UPDATE clientes SET nome = %s, email = %s, telefone = %s WHERE id = %s AND usuario_id = %s",
                    (nome, email, telefone, id, session['user_id'])
                )

            flash('Cliente atualizado com sucesso!', 'success')
            return redirect(url_for('listar_clientes'))

        except Exception as e:
            flash(f'Erro ao atualizar cliente: {str(e)}', 'danger')
            return redirect(url_for('editar_cliente', id=id))


@clientes_bp.route('/buscar_clientes', endpoint='buscar_clientes')
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


@clientes_bp.route('/exportar_clientes_csv', endpoint='exportar_clientes_csv')
@login_required
def exportar_clientes_csv():
    clientes = db_query(
        "SELECT id, nome, email, telefone, created_at FROM clientes WHERE usuario_id = %s ORDER BY nome ASC",
        (session['user_id'],)
    )
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['ID', 'Nome', 'Email', 'Telefone', 'Data de Cadastro'])
    for cl in clientes:
        writer.writerow([cl['id'], cl['nome'], cl['email'] or '', cl['telefone'] or '', cl['created_at']])

    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=clientes.csv'}
    )
