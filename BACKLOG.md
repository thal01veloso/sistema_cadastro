# Backlog do Projeto — ClientSys (`sistema_cadastro`)

Este documento reúne o mapeamento completo de correções de bugs, melhorias de segurança, refatorações arquiteturais, aprimoramentos de UX/UI e novas funcionalidades para evolução do sistema.

---

## 🔴 Prioridade 1: Correção de Bugs e Falhas de Segurança (Crítico)

Itens que resolvem vulnerabilidades de controle de acesso, problemas funcionais imediatos e falhas de marcação HTML/JS.

- [x] **[SEC-01] Corrigir vulnerabilidade IDOR na edição de clientes (`POST`)**
  - **Arquivo:** `app.py` (função `editar_cliente`)
  - **Problema:** O método `GET` valida `usuario_id`, mas o `POST` busca a foto antiga e executa `UPDATE clientes ... WHERE id = %s` sem verificar `AND usuario_id = %s`, permitindo que um usuário autenticado altere clientes de terceiros.
- [x] **[SEC-02] Corrigir vulnerabilidade IDOR no envio de cobranças**
  - **Arquivo:** `app.py` (função `enviar_cobranca`)
  - **Problema:** A consulta `SELECT` e o `UPDATE cobrancas` filtram apenas por `c.id = %s`, sem validar se a cobrança pertence ao `session['user_id']`.
- [x] **[SEC-03] Implementar proteção contra CSRF (Cross-Site Request Forgery)**
  - **Arquivos:** `app.py` e todos os templates com formulários `POST` (`login.html`, `registrar.html`, `cadastrar.html`, `editar.html`, `agendar_cobranca.html`, `_clientes_partial.html`, `perfil.html`, `detalhes.html`, `listar_cobrancas.html`, `dashboard.html`).
  - **Solução:** Implementada validação `@app.before_request` (`csrf_protect`) com `secrets.compare_digest` e `csrf_token()` global no Jinja2.
- [x] **[SEC-04] Evitar colisão e sobrescrita de arquivos no upload de fotos**
  - **Arquivo:** `app.py` (funções `cadastrar_clientes` e `editar_cliente`)
  - **Problema:** Usar apenas `secure_filename(file.filename)` faz com que dois clientes que enviem imagens com o mesmo nome sobrescrevam o arquivo um do outro, e a exclusão de um apague a foto do outro.
  - **Solução:** Gerar nomes únicos com `uuid.uuid4().hex` mantendo a extensão original.
- [x] **[SEC-05] Proteger rota de arquivos de upload**
  - **Arquivos:** `app.py` (função `uploaded_file`)
  - **Problema:** A rota `/uploads/<filename>` não exigia `@login_required` nem sanitizava o nome do arquivo com `secure_filename`.
- [x] **[BUG-01] Corrigir HTML truncado no menu de navegação e adicionar Menu Lateral (Sidebar)**
  - **Arquivo:** `templates/base.html` e `static/style.css`
  - **Problema:** A tag `<a href="{{ url_for('listar_cobrancas') }}"><i class="fas fa-calendar-alt"></i> Cobr` estava incompleta, quebrando o cabeçalho. Convertido para menu lateral responsivo completo.
- [x] **[BUG-02] Corrigir confirmação de envio de cobrança na tela de agendamento**
  - **Arquivo:** `templates/agendar_cobranca.html` (linha 67)
  - **Problema:** O atributo `onclick` usava `{{ cobranca.cliente_nome }}`, mas a query da rota `agendar_cobranca` fornece o nome em `{{ cliente.nome }}`.
- [x] **[BUG-03] Corrigir posicionamento de tags `<script>` fora do `<body>` e duplicação de listeners**
  - **Arquivo:** `templates/base.html`
  - **Problema:** Havia blocos `<script>` entre `</head>` e `<body>` e após `</body>`, além de dois listeners diferentes para o mesmo input `#foto`.
- [x] **[BUG-04] Corrigir fallback de imagem inexistente e rota de `favicon.ico`**
  - **Arquivo:** `app.py` (funções `uploaded_file` e `favicon`)
  - **Problema:** Redirecionava para `static/img/default-user.png` e `static/favicon.ico` sem verificar existência, gerando erro 404/500.

---

## 🟠 Prioridade 2: Qualidade de Código, Arquitetura e Banco de Dados

Melhorias estruturais para tornar o projeto modular, padronizado e fácil de manter.

- [x] **[ARQ-01] Modularizar a aplicação com Flask Blueprints e Application Factory**
  - **Arquivos:** `app.py`, `config.py`, `database.py`, `routes/auth.py`, `routes/clientes.py`, `routes/cobrancas.py`
  - **Solução:** Separadas as responsabilidades em pacotes/módulos utilizando o padrão `create_app()` e Blueprints.
- [x] **[ARQ-02] Limpar e enxugar o `requirements.txt`**
  - **Arquivo:** `requirements.txt`
  - **Problema:** Removidos pacotes não utilizados pelo projeto (`pandas`, `numpy`, `virtualenv`, `distlib`, `filelock` e a duplicidade entre `dotenv` e `python-dotenv`).
- [x] **[ARQ-03] Padronizar classes CSS nos templates**
  - **Arquivos:** `templates/cadastrar.html`, `templates/detalhes.html`, `templates/agendar_cobranca.html`, `templates/listar_cobrancas.html` e `static/style.css`
  - **Problema:** Padronizados os templates para utilizar o design system próprio em `static/style.css`.
- [x] **[ARQ-04] Alterar rota de envio de cobrança para `POST`**
  - **Arquivo:** `app.py` (função `enviar_cobranca`) e templates
  - **Solução:** Convertido o disparo de cobranças nos templates em formulários `POST` protegidos por CSRF.
- [x] **[DB-01] Padronizar script SQL e criar comando de inicialização do banco**
  - **Arquivo:** `schema.txt` e `app.py`
  - **Solução:** Definido `ENUM('pendente', 'enviada', 'paga', 'cancelada')`, adicionadas colunas de template/PIX e criado o comando `flask init-db`.

---

## 🟡 Prioridade 3: Melhorias de UX/UI e Fluxos Existentes

Ajustes para completar fluxos parciais e melhorar a usabilidade no dia a dia.

- [x] **[UX-01] Ativar e integrar a página de Detalhes do Cliente**
  - **Arquivos:** `templates/detalhes.html`, `templates/_clientes_partial.html` e `app.py`
  - **Solução:** Criada a rota `/cliente/<int:id>`, exibindo a foto real do cliente, resumo financeiro de cobranças, histórico detalhado e botão "Detalhes" nos cards de clientes.
- [x] **[UX-02] Gestão completa do ciclo de vida da Cobrança (Marcar como Paga, Reenviar e Excluir)**
  - **Arquivos:** `app.py`, `templates/detalhes.html` e `templates/listar_cobrancas.html`
  - **Solução:** Adicionadas rotas `/cobranca/<id>/status` e `/excluir_cobranca/<id>`, permitindo dar baixa como `paga`, reenviar pelo WhatsApp e excluir cobranças.
- [x] **[UX-03] Máscara de telefone automática no Frontend**
  - **Arquivos:** `templates/base.html`, `templates/cadastrar.html` e `templates/editar.html`
  - **Solução:** Aplicada máscara dinâmica `(99) 99999-9999` nos inputs de telefone.
- [x] **[UX-04] Ajustar tempo de exibição nos alertas Flash**
  - **Arquivo:** `templates/base.html`
  - **Solução:** Tempo de exibição ampliado para `4000ms` (4 segundos) com transição suave.
- [x] **[UX-05] Filtros avançados na listagem de cobranças**
  - **Arquivos:** `app.py` e `templates/listar_cobrancas.html`
  - **Solução:** Implementados filtros por status (`pendente`, `enviada`, `paga`, `cancelada`) e busca por nome do cliente na listagem de cobranças.

---

## 🟢 Prioridade 4: Novas Funcionalidades (Evolução do Produto)

Recursos para transformar o projeto em uma solução completa de gestão de clientes e cobranças.

- [x] **[FEAT-01] Dashboard Financeiro Inicial**
  - **Descrição:** Painel com indicadores rápidos (KPIs): Total de clientes, clientes com WhatsApp, valor pendente, total já cobrado, cobranças vencidas/atrasadas, taxa de disparo, próximas cobranças e ranking de principais clientes.
- [x] **[FEAT-02] Templates personalizáveis de mensagem de WhatsApp**
  - **Descrição:** Configuração em `/perfil` permitindo personalizar o modelo de mensagem e Chave PIX com variáveis dinâmicas (`{nome}`, `{valor}`, `{data_agendamento}`, `{descricao}`, `{chave_pix}`).
- [x] **[FEAT-03] Exportação de Dados (CSV)**
  - **Descrição:** Exportação de clientes (`/exportar_clientes_csv`) e relatório de cobranças (`/exportar_cobrancas_csv`) compatíveis com Excel (UTF-8 BOM).
- [x] **[FEAT-04] Página de Perfil do Usuário e Alteração de Senha**
  - **Descrição:** Tela `/perfil` para o usuário logado atualizar seus dados cadastrais e trocar sua senha com validação da senha atual.
- [x] **[FEAT-05] Documentação do Projeto (`README.md`)**
  - **Descrição:** Documentação completa no `README.md` com instruções de instalação, configuração do banco e execução.
