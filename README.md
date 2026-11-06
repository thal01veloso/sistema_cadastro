# ClientSys — Sistema de Gestão de Clientes e Cobranças

Aplicação web desenvolvida em **Python (Flask)** e **MySQL** para controle de carteira de clientes, agendamento de cobranças e disparo rápido de notificações via **WhatsApp**, contando com painel de indicadores (**Dashboard**) e suporte multiusuário.

---

## Principais Funcionalidades

- **Dashboard com KPIs Financeiros:** Visão consolidada do total de clientes, clientes com WhatsApp, valores pendentes, enviados, vencidos/atrasados, taxa de envio e ranking de clientes.
- **Gestão Completa de Clientes (CRUD):** Cadastro com foto de perfil, busca em tempo real por nome (AJAX), máscara automática de telefone, tela de detalhes com resumo individual e exportação em CSV.
- **Agendamento e Controle de Cobranças:** Agendamento com data/hora, filtros por status (`pendente`, `enviada`, `paga`, `cancelada`) e por nome de cliente, baixa manual como paga, exclusão e exportação de relatório CSV.
- **Integração com WhatsApp:** Geração automática de mensagem formatada e redirecionamento para o WhatsApp (`wa.me`) com atualização do status e data/hora de envio.
- **Autenticação e Perfil:** Cadastro de usuários com hash seguro (`pbkdf2:sha256`), isolamento de dados por usuário logado e página de perfil para atualização cadastral e troca de senha.

---

## Pré-requisitos

- **Python 3.10+**
- **MySQL Server 8.0+** (ou MariaDB)

---

## Como Executar Localmente

1. **Configure o Banco de Dados MySQL:**
   Execute o script SQL contido em [`schema.txt`](schema.txt) no seu servidor MySQL para criar o banco `sistema_cobrancas` e as tabelas `usuarios`, `clientes` e `cobrancas`.

2. **Configure as Variáveis de Ambiente:**
   Copie o arquivo `.envExemple` para `.env` e preencha com suas credenciais do MySQL:
   ```env
   SECRET_KEY="sua_chave_secreta"
   MYSQL_HOST="localhost"
   MYSQL_USER="root"
   MYSQL_PASSWORD="sua_senha"
   MYSQL_DB="sistema_cobrancas"
   FLASK_DEBUG="True"
   ```

3. **Crie o Ambiente Virtual e Instale as Dependências:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\pip install -r requirements.txt
   ```

4. **Inicie o Servidor:**
   ```powershell
   .\venv\Scripts\python app.py
   ```
   Acesse no navegador: `http://127.0.0.1:5000`
