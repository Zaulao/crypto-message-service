# Sistema Seguro de Troca de Mensagens (Modelo Cliente-Servidor E2EE)

Esta é a versão 2.0 do projeto, que implementa um modelo de Criptografia de Ponta a Ponta (E2EE). Nesta arquitetura, o servidor **não possui as chaves privadas** e, portanto, **não pode ler as mensagens dos usuários**. Toda a criptografia, decriptografia e assinatura ocorrem no lado do cliente.

## Arquitetura

- **API (Servidor - `main.py`)**: Atua como um diretório de chaves públicas e uma "caixa de correio" para armazenar e encaminhar envelopes de mensagens seladas.
- **CLI (Cliente - `cli.py`)**: Aplicação operada pelo usuário. Gerencia as chaves privadas localmente e executa todas as operações criptográficas sensíveis.

---

## Como Executar

### 1. Instalação

O processo é o mesmo, mas agora instalaremos as dependências para ambos, cliente e servidor.

```bash
# Crie e ative um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instale todas as dependências
pip install -r requirements.txt
```

### 2. Iniciando o Servidor

Em um terminal, inicie a API do servidor:

```bash
uvicorn main:app --reload
```

O servidor estará rodando em [http://127.0.0.1:8000](http://127.0.0.1:8000).  
Você ainda pode acessar a documentação em [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) para ver os endpoints, mas a interação principal será via CLI.

---

### 3. Usando o Cliente CLI

Abra um novo terminal (deixe o servidor rodando no primeiro). Todas as operações a seguir são feitas com o `cli.py`.

#### Passo 1: Criar Usuários

Use o comando `create-user` para cada usuário. A CLI irá contatar a API e salvar a chave privada recebida localmente.

```bash
python cli.py create-user alice
# Saída: Chave privada para 'alice' salva com segurança em: /home/user/.secure_message_client/keys/alice_priv.pem

python cli.py create-user bob
python cli.py create-user carol
```

Verifique o diretório `~/.secure_message_client/keys/` para ver os arquivos PEM das chaves privadas.

#### Passo 2: Enviar uma Mensagem

Use o comando `send`. A CLI fará todo o trabalho de assinar, criptografar e enviar para a API.

```bash
python cli.py send --sender alice --to bob --to carol --message "Reunião confirmada para amanhã às 10h. E2EE."
```

#### Passo 3: Ler as Mensagens

Cada usuário usa o comando `read` com seu próprio nome de usuário. A CLI buscará os envelopes na API, os decriptografará localmente com a chave privada e verificará as assinaturas.

```bash
# Bob lendo suas mensagens
python cli.py read bob

# Saída esperada:
# Você tem 1 mensagem(ns):
# Verificando assinatura de 'alice'...
# ----------------------------------------
# De: alice
# Data: 2025-10-21T01:32:00.123456+00:00
# Mensagem: Reunião confirmada para amanhã às 10h. E2EE.
# Assinatura: VÁLIDA ✓
# ----------------------------------------

# Carol lendo suas mensagens
python cli.py read carol
```

#### Passo 4: Consultar o Log da API

Você ainda pode usar a interface web ([http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)) ou uma ferramenta como `curl` para verificar o log de auditoria no servidor e ver os eventos que ele registrou (criação de usuários, armazenamento de mensagens, etc.).

```bash
curl http://127.0.0.1:8000/audit-log
```

---

> Isso demonstra a separação clara: o cliente lida com o conteúdo e a segurança, enquanto o servidor lida com os metadados e a infraestrutura.
