"""
Este é o programa que o usuário final irá operar. Ele é responsável por:
- Gerenciar as chaves privadas do usuário localmente.
- Interagir com a API do servidor.
- Realizar todas as operações criptográficas sensíveis (assinatura e decriptografia).
"""

import os
import json
import base64
from datetime import datetime, timezone
import click
import requests

# Importa o mesmo serviço de criptografia usado pela API
import crypto_service

# --- Configurações do Cliente ---
API_BASE_URL = "http://127.0.0.1:8000"
CLIENT_DIR = "secure_message_client"
KEYS_DIR = os.path.join(CLIENT_DIR, "keys")

def setup_client_dirs():
    """Garante que os diretórios do cliente existam."""
    os.makedirs(KEYS_DIR, exist_ok=True)

def save_private_key(username: str, private_key_pem: str):
    """Salva a chave privada do usuário localmente."""
    setup_client_dirs()
    path = os.path.join(KEYS_DIR, f"{username}_priv.pem")
    with open(path, "w") as f:
        f.write(private_key_pem)
    os.chmod(path, 0o600)
    click.echo(f"Chave privada para '{username}' salva com segurança em: {path}")

def load_private_key(username: str):
    """Carrega a chave privada do usuário do arquivo local."""
    path = os.path.join(KEYS_DIR, f"{username}_priv.pem")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Chave privada para '{username}' não encontrada. Crie o usuário primeiro com 'create-user'.")
    with open(path, "rb") as f:
        return crypto_service.deserialize_private_key(f.read())

def get_public_key_from_api(username: str):
    """Busca a chave pública de um usuário na API."""
    response = requests.get(f"{API_BASE_URL}/keys/{username}")
    response.raise_for_status()
    return crypto_service.deserialize_public_key(response.json()["public_key_pem"].encode('utf-8'))

# --- Comandos do CLI usando Click ---

@click.group()
def cli():
    """Cliente de linha de comando para o sistema de mensagens seguras."""
    pass

@cli.command("create-user")
@click.argument("username")
def create_user(username: str):
    """
    Cria um novo usuário na API, recebe a chave privada e a salva localmente.
    """
    click.echo(f"Criando usuário '{username}' no servidor...")
    try:
        response = requests.post(f"{API_BASE_URL}/users", json={"username": username})
        if response.status_code == 409:
            click.secho(f"Erro: Usuário '{username}' já existe no servidor.", fg="red")
            return
        response.raise_for_status()
        data = response.json()
        save_private_key(username, data["private_key_pem"])
        click.secho(f"Usuário '{username}' criado com sucesso!", fg="green")
    except requests.exceptions.RequestException as e:
        click.secho(f"Erro de comunicação com a API: {e}", fg="red")

@cli.command("send")
@click.option("--sender", required=True, help="O seu nome de usuário (remetente).")
@click.option("--to", "recipients", multiple=True, required=True, help="Destinatário(s) da mensagem.")
@click.option("--message", required=True, help="A mensagem a ser enviada.")
def send_message(sender: str, recipients: list, message: str):
    """
    Envia uma mensagem segura. Todo o trabalho criptográfico é feito aqui, no cliente.
    """
    try:
        click.echo(f"Preparando mensagem de '{sender}' para {recipients}...")
        
        # 1. Carregar a chave privada do remetente
        sender_private_key = load_private_key(sender)

        # 2. Criar e assinar o pacote interno
        inner_package = {
            "sender_id": sender,
            "plaintext_message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        inner_package_bytes = json.dumps(inner_package, sort_keys=True).encode('utf-8')
        signature = crypto_service.sign_data(inner_package_bytes, sender_private_key)
        
        inner_package_with_signature = {
            "payload": inner_package,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        final_payload_bytes = json.dumps(inner_package_with_signature).encode('utf-8')

        # 3. Criptografia híbrida
        aes_key = crypto_service.generate_aes_key()
        ciphertext, iv, tag = crypto_service.encrypt_aes_gcm(final_payload_bytes, aes_key)

        # 4. Criptografar a chave AES para cada destinatário
        encrypted_keys = {}
        for recipient in recipients:
            click.echo(f"Buscando chave pública de '{recipient}'...")
            recipient_public_key = get_public_key_from_api(recipient)
            encrypted_aes_key = crypto_service.encrypt_rsa(aes_key, recipient_public_key)
            encrypted_keys[recipient] = base64.b64encode(encrypted_aes_key).decode('utf-8')

        # 5. Montar o envelope final
        envelope = {
            "sender": sender,
            "recipients": list(recipients),
            "encrypted_payload": {
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
            },
            "encrypted_keys": encrypted_keys
        }

        # 6. Enviar o envelope selado para a API
        click.echo("Enviando envelope selado para a API...")
        response = requests.post(f"{API_BASE_URL}/messages", json=envelope)
        response.raise_for_status()
        click.secho("Mensagem enviada com sucesso!", fg="green")

    except FileNotFoundError as e:
        click.secho(f"Erro: {e}", fg="red")
    except requests.exceptions.RequestException as e:
        click.secho(f"Erro de comunicação com a API: {e}", fg="red")

@cli.command("read")
@click.argument("username")
def read_messages(username: str):
    """
    Busca, decriptografa e verifica mensagens para o usuário especificado.
    """
    try:
        click.echo(f"Buscando mensagens para '{username}'...")
        # 1. Carregar a chave privada do usuário
        private_key = load_private_key(username)

        # 2. Buscar envelopes da API
        response = requests.get(f"{API_BASE_URL}/messages/{username}")
        response.raise_for_status()
        messages = response.json()

        if not messages:
            click.echo("Nenhuma mensagem nova.")
            return

        click.secho(f"Você tem {len(messages)} mensagem(ns):", bold=True)
        
        # 3. Processar cada envelope localmente
        for msg in messages:
            envelope = msg["envelope"]
            try:
                # 3a. Descriptografar a chave AES
                encrypted_aes_key = base64.b64decode(envelope["encrypted_keys"][username])
                aes_key = crypto_service.decrypt_rsa(encrypted_aes_key, private_key)

                # 3b. Descriptografar o payload
                payload_data = envelope["encrypted_payload"]
                ciphertext = base64.b64decode(payload_data["ciphertext"])
                iv = base64.b64decode(payload_data["iv"])
                tag = base64.b64decode(payload_data["tag"])
                inner_package_bytes = crypto_service.decrypt_aes_gcm(ciphertext, aes_key, iv, tag)
                inner_package_with_sig = json.loads(inner_package_bytes)

                # 3c. Verificar a assinatura
                payload = inner_package_with_sig["payload"]
                sender_id = payload["sender_id"]
                signature = base64.b64decode(inner_package_with_sig["signature"])
                
                click.echo(f"Verificando assinatura de '{sender_id}'...")
                sender_public_key = get_public_key_from_api(sender_id)
                payload_str_to_verify = json.dumps(payload, sort_keys=True).encode('utf-8')
                is_valid = crypto_service.verify_signature(payload_str_to_verify, signature, sender_public_key)

                # 3d. Exibir a mensagem
                click.echo("-" * 40)
                click.echo(f"De: {click.style(sender_id, fg='yellow')}")
                click.echo(f"Data: {payload['timestamp']}")
                click.echo(f"Mensagem: {payload['plaintext_message']}")
                if is_valid:
                    click.secho("Assinatura: VÁLIDA ✓", fg="green")
                else:
                    click.secho("Assinatura: INVÁLIDA ✗", fg="red", bold=True)
                click.echo("-" * 40)

            except Exception as e:
                click.secho(f"Não foi possível processar a mensagem {msg['id']}: {e}", fg="red")

    except FileNotFoundError as e:
        click.secho(f"Erro: {e}", fg="red")
    except requests.exceptions.RequestException as e:
        click.secho(f"Erro de comunicação com a API: {e}", fg="red")


if __name__ == "__main__":
    cli()
