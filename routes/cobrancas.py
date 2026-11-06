import csv
import io
from datetime import datetime
from urllib.parse import quote
from flask import Blueprint, Response, flash, redirect, render_template, request, session, url_for
from config import DEFAULT_WHATSAPP_TEMPLATE
from database import db_commit, db_query, logger, login_required

cobrancas_bp = Blueprint('cobrancas', __name__)


@cobrancas_bp.route('/agendar_cobranca/<int:cliente_id>', methods=['GET', 'POST'], endpoint='agendar_cobranca')
@login_required
def agendar_cobranca(cliente_id):
    cliente = db_query(
        "SELECT * FROM clientes WHERE id = %s AND usuario_id = %s",
        (cliente_id, session['user_id']),
        fetchone=True
    )

    if not cliente:
        flash('Cliente não encontrado ou permissão negada!', 'danger')
        return redirect(url_for('listar_clientes'))

    cobrancas = db_query(
        """SELECT id, valor, descricao, status, 
           DATE_FORMAT(data_agendamento, '%%d/%%m/%%Y %%H:%%i') as data_formatada,
           data_envio
           FROM cobrancas 
           WHERE cliente_id = %s
           ORDER BY data_agendamento DESC""",
        (cliente_id,)
    )

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
                """INSERT INTO cobrancas 
                   (cliente_id, valor, descricao, data_agendamento, usuario_id) 
                   VALUES (%s, %s, %s, %s, %s)""",
                (cliente_id, valor_float, descricao, data_obj, session['user_id'])
            )

            flash('Cobrança agendada com sucesso!', 'success')
            return redirect(url_for('agendar_cobranca', cliente_id=cliente_id))

        except Exception as e:
            flash(f'Erro ao agendar cobrança: {str(e)}', 'danger')
            return redirect(url_for('agendar_cobranca', cliente_id=cliente_id))

    return render_template('agendar_cobranca.html', cliente=cliente, cobrancas=cobrancas)


@cobrancas_bp.route('/enviar_cobranca/<int:cobranca_id>', methods=['GET', 'POST'], endpoint='enviar_cobranca')
@login_required
def enviar_cobranca(cobranca_id):
    try:
        cobranca = db_query(
            """SELECT c.id, c.valor, c.descricao, c.status,
                      DATE_FORMAT(c.data_agendamento, '%%d/%%m/%%Y %%H:%%i') as data_formatada,
                      cl.nome, cl.telefone, cl.id as cliente_id
               FROM cobrancas c
               JOIN clientes cl ON c.cliente_id = cl.id
               WHERE c.id = %s AND cl.usuario_id = %s""",
            (cobranca_id, session['user_id']),
            fetchone=True
        )

        if not cobranca:
            flash('Cobrança não encontrada ou permissão negada!', 'danger')
            return redirect(url_for('listar_cobrancas'))

        telefone = cobranca['telefone']
        if not telefone:
            flash('Cliente não possui telefone cadastrado!', 'danger')
            return redirect(url_for('listar_cobrancas'))

        telefone = ''.join(filter(str.isdigit, str(telefone)))
        if len(telefone) < 11:
            flash('Número de telefone inválido!', 'danger')
            return redirect(url_for('listar_cobrancas'))

        if not telefone.startswith('55') and len(telefone) <= 11:
            telefone = '55' + telefone.lstrip('0')

        template_texto = session.get('template_whatsapp') or DEFAULT_WHATSAPP_TEMPLATE
        chave_pix = session.get('chave_pix') or 'Consulte-nos'
        try:
            user_cfg = db_query(
                "SELECT chave_pix, template_whatsapp FROM usuarios WHERE id = %s",
                (session['user_id'],),
                fetchone=True
            )
            if user_cfg:
                if user_cfg.get('template_whatsapp'):
                    template_texto = user_cfg['template_whatsapp']
                if user_cfg.get('chave_pix'):
                    chave_pix = user_cfg['chave_pix']
        except Exception:
            pass

        try:
            mensagem = template_texto.format(
                nome=cobranca['nome'],
                valor=f"{float(cobranca['valor']):.2f}",
                descricao=cobranca['descricao'] or 'Serviço/Mensalidade',
                data_agendamento=cobranca.get('data_formatada') or '',
                chave_pix=chave_pix
            )
        except Exception:
            mensagem = (
                f"*Cobrança - {cobranca['nome']}*\n\n"
                f"💰 *Valor:* R$ {float(cobranca['valor']):.2f}\n"
                f"Por favor, efetue o pagamento o mais breve possível."
            )

        mensagem_codificada = quote(mensagem)
        whatsapp_url = f"https://wa.me/{telefone}?text={mensagem_codificada}"

        db_commit(
            "UPDATE cobrancas SET status = 'enviada', data_envio = NOW() WHERE id = %s AND usuario_id = %s",
            (cobranca_id, session['user_id'])
        )

        logger.info(f"Enviando cobrança para {telefone}: {mensagem}")
        return redirect(whatsapp_url)

    except Exception as e:
        logger.error(f"Erro ao enviar cobrança: {str(e)}", exc_info=True)
        flash(f'Erro ao enviar cobrança: {str(e)}', 'danger')
        return redirect(url_for('listar_cobrancas'))


@cobrancas_bp.route('/listar_cobrancas', endpoint='listar_cobrancas')
@login_required
def listar_cobrancas():
    status_filtro = request.args.get('status', '').strip()
    busca_cliente = request.args.get('cliente', '').strip()

    query = """
        SELECT c.id, c.valor, c.descricao, c.status,
               DATE_FORMAT(c.data_agendamento, '%%d/%%m/%%Y %%H:%%i') as data_formatada,
               cl.nome as cliente_nome, 
               cl.id as cliente_id,
               cl.telefone
        FROM cobrancas c
        JOIN clientes cl ON c.cliente_id = cl.id
        WHERE cl.usuario_id = %s
    """
    params = [session['user_id']]

    if status_filtro in ('pendente', 'enviada', 'paga', 'cancelada'):
        query += " AND c.status = %s"
        params.append(status_filtro)

    if busca_cliente:
        query += " AND cl.nome LIKE %s"
        params.append(f"%{busca_cliente}%")

    query += " ORDER BY c.data_agendamento DESC"

    cobrancas = db_query(query, tuple(params))
    return render_template(
        'listar_cobrancas.html',
        cobrancas=cobrancas,
        status_filtro=status_filtro,
        busca_cliente=busca_cliente
    )


@cobrancas_bp.route('/exportar_cobrancas_csv', endpoint='exportar_cobrancas_csv')
@login_required
def exportar_cobrancas_csv():
    cobrancas = db_query(
        """SELECT c.id, cl.nome AS cliente_nome, cl.telefone, c.valor, c.descricao, c.status,
                  DATE_FORMAT(c.data_agendamento, '%%d/%%m/%%Y %%H:%%i') AS data_agendamento,
                  DATE_FORMAT(c.data_envio, '%%d/%%m/%%Y %%H:%%i') AS data_envio
           FROM cobrancas c
           JOIN clientes cl ON c.cliente_id = cl.id
           WHERE cl.usuario_id = %s
           ORDER BY c.data_agendamento DESC""",
        (session['user_id'],)
    )
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['ID', 'Cliente', 'Telefone', 'Valor (R$)', 'Descricao', 'Status', 'Data Agendada', 'Data Envio'])
    for cob in cobrancas:
        writer.writerow([
            cob['id'],
            cob['cliente_nome'],
            cob['telefone'] or '',
            f"{float(cob['valor']):.2f}",
            cob['descricao'] or '',
            cob['status'],
            cob['data_agendamento'] or '',
            cob['data_envio'] or ''
        ])

    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=cobrancas.csv'}
    )


@cobrancas_bp.route('/cobranca/<int:cobranca_id>/status', methods=['POST'], endpoint='alterar_status_cobranca')
@login_required
def alterar_status_cobranca(cobranca_id):
    novo_status = request.form.get('status', '').strip()
    if novo_status not in ('pendente', 'enviada', 'paga', 'cancelada'):
        flash('Status inválido!', 'danger')
        return redirect(request.referrer or url_for('listar_cobrancas'))

    try:
        db_commit(
            "UPDATE cobrancas SET status = %s WHERE id = %s AND usuario_id = %s",
            (novo_status, cobranca_id, session['user_id'])
        )
        flash(f'Cobrança marcada como {novo_status}!', 'success')
    except Exception as e:
        flash(f'Erro ao atualizar cobrança: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('listar_cobrancas'))


@cobrancas_bp.route('/excluir_cobranca/<int:cobranca_id>', methods=['POST'], endpoint='excluir_cobranca')
@login_required
def excluir_cobranca(cobranca_id):
    try:
        db_commit(
            "DELETE FROM cobrancas WHERE id = %s AND usuario_id = %s",
            (cobranca_id, session['user_id'])
        )
        flash('Cobrança excluída com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao excluir cobrança: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('listar_cobrancas'))
