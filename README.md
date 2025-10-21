# Sistema Seguro de Troca de Mensagens

Este projeto é uma API desenvolvida em Python com FastAPI para demonstrar um sistema de troca de mensagens seguro, utilizando criptografia híbrida (RSA + AES), assinaturas digitais (RSA-PSS) e um log de auditoria à prova de adulteração.

## Estrutura do Projeto

- `main.py`: A aplicação FastAPI com todos os endpoints da API.

- `crypto_service.py`: Módulo de baixo nível com todas as funções criptográficas (geração de chaves, criptografia, assinatura, etc.).

- `message_service.py`: Módulo de alto nível que orquestra a lógica de envio e recebimento de mensagens.

- `key_manager.py`: Gerencia a criação e o acesso às chaves dos usuários.

- `storage_manager.py`: Gerencia o acesso seguro a arquivos JSON que funcionam como nosso banco de dados.

- `audit_log.py`: Implementa o log de auditoria assinado digitalmente.

- `requirements.txt`: Lista de dependências Python.

- `keys/`: Diretório onde as chaves privadas (dos usuários e da auditoria) são armazenadas.

- `data/`: Diretório onde os "bancos de dados" JSON (chaves públicas, mensagens) e o log de auditoria são armazenados.

## Como Executar

1. Pré-requisitos

- Python 3.8 ou superior
- `pip` (gerenciador de pacotes Python)

2. Instalação

Clone o repositório e instale as dependências:

```bash
# Crie e ative um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instale as dependências
pip install -r requirements.txt
```

3. Iniciando o Servidor

Execute o servidor da API usando Uvicorn:

```bash
uvicorn main:app --reload
```

O servidor estará rodando em `http://127.0.0.1:8000`. A opção `--reload` faz com que o servidor reinicie automaticamente após qualquer alteração no código.

4. Usando a API (Demonstração)

Abra seu navegador e acesse a documentação interativa da API em:

[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

A partir desta interface, você pode executar todos os passos para demonstrar o sistema:

## Passo 1: Criar Usuários

Vá para o endpoint `POST /create-user`.

- Clique em "Try it out".
- No corpo da requisição, crie os usuários alice, bob e carol, um de cada vez.

```json
{
  "username": "alice"
}
```
- Clique em "Execute" para cada um. Isso irá gerar seus pares de chaves.

## Passo 2: Enviar uma Mensagem

- Vá para o endpoint `POST /send-message`.
- Clique em "Try it out".
- Preencha o corpo da requisição para que `alice` envie uma mensagem para `bob` e `carol`.

```json
{
  "sender": "alice",
  "recipients": [
    "bob",
    "carol"
  ],
  "message": "Olá, Bob e Carol! Nossa reunião será às 15h. Ass: Alice"
}
```
- Clique em "Execute".

## Passo 3: Inspecionar os Dados Armazenados (Opcional)

- Abra os arquivos no diretório `data/` em um editor de texto.
- `data/public_keys.json`: Você verá as chaves públicas de Alice, Bob e Carol em formato PEM.
- `data/messages.json`: Você verá o "envelope" da mensagem. Note que tudo está cifrado (ciphertext) e que existe uma chave AES criptografada (encrypted_keys) para Bob e outra para Carol.

## Passo 4: Ler a Mensagem

- Vá para o endpoint `GET /messages/{username}`.
- Clique em "Try it out".
- Digite `bob` no campo username e clique em "Execute".
- Você verá a mensagem de Alice descriptografada, junto com o status `signature_valid: true`.
- Agora, repita o processo para `carol`. Ela também conseguirá ler a mesma mensagem.

## Passo 5: Consultar o Log de Auditoria

- Vá para o endpoint `GET /audit-log`.
- Clique em "Try it out" e depois em "Execute".
- Você verá o log completo de todas as ações (criação de usuários, envio e leitura de mensagens), junto com o status `log_is_valid: true`.

## Passo 6: Testar a Segurança (Opcional)

- Abra o arquivo `data/messages.json` e altere um único caractere no ciphertext da mensagem.
- Tente ler a mensagem novamente como Bob ou Carol. A API retornará um erro, pois a tag de autenticação do AES-GCM não será mais válida, provando a garantia de integridade.
- Restaure o arquivo `messages.json` original.
- Abra `data/audit_log.jsonl` e altere um caractere em uma das linhas.
- Execute o endpoint `GET /audit-log` novamente. Ele agora retornará `log_is_valid: false`, provando que a adulteração foi detectada.