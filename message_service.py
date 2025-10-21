"""
Este é o coração da aplicação, orquestrando a lógica de alto nível para
enviar e receber mensagens seguras. Ele combina os primitivos do
`crypto_service` para implementar o fluxo de criptografia híbrida e
assinatura digital.
"""

import json
import base64
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

import crypto_service
import key_manager
import storage_manager
import audit_log

def send_message(sender_username: str, recipient_usernames: List[str], plaintext_message: str):
    """
    Processo completo para enviar uma mensagem segura para múltiplos destinatários.
    
    Workflow:
    1.  Cria um "pacote interno" com a mensagem, dados do remetente e timestamp.
    2.  Assina este pacote com a chave privada do remetente (garante autenticidade e não-repúdio).
    3.  Gera uma chave de sessão AES única para esta mensagem.
    4.  Criptografa o pacote interno (já assinado) com a chave AES (garante confidencialidade).
    5.  Para cada destinatário:
        a. Obtém sua chave pública.
        b. Criptografa a chave de sessão AES com a chave pública do destinatário.
    6.  Monta o "envelope final" contendo o payload criptografado e as chaves de sessão
        criptografadas para cada destinatário.
    7.  Salva o envelope no armazenamento.
    """
    # Carrega a chave privada do remetente
    sender_private_key = key_manager.get_private_key(sender_username)

    # 1. Criar o "pacote interno" (dados que serão assinados e depois criptografados)
    inner_package = {
        "sender_id": sender_username,
        "plaintext_message": plaintext_message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # A serialização com `sort_keys=True` garante que a representação em bytes
    # seja sempre a mesma, o que é vital para a assinatura.
    inner_package_str = json.dumps(inner_package, sort_keys=True)
    inner_package_bytes = inner_package_str.encode('utf-8')

    # 2. Assinar o pacote interno
    signature = crypto_service.sign_data(inner_package_bytes, sender_private_key)
    
    # Adiciona a assinatura ao pacote
    inner_package_with_signature = {
        "payload": inner_package,
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    final_payload_bytes = json.dumps(inner_package_with_signature).encode('utf-8')

    # 3. Gerar uma chave de sessão AES única (one-time key)
    aes_key = crypto_service.generate_aes_key()

    # 4. Criptografar o pacote com a chave AES
    ciphertext, iv, tag = crypto_service.encrypt_aes_gcm(final_payload_bytes, aes_key)

    # 5. Criptografar a chave AES para cada destinatário
    encrypted_keys = {}
    for recipient in recipient_usernames:
        try:
            recipient_public_key = key_manager.get_public_key(recipient)
            encrypted_aes_key = crypto_service.encrypt_rsa(aes_key, recipient_public_key)
            encrypted_keys[recipient] = base64.b64encode(encrypted_aes_key).decode('utf-8')
        except FileNotFoundError:
            print(f"AVISO: Destinatario '{recipient}' não encontrado. A mensagem nao sera enviada a este destinatario.")
            continue
    
    if not encrypted_keys:
        raise ValueError("Nenhum destinatario valido encontrado. Mensagem não enviada.")

    # 6. Montar o envelope final
    message_id = str(uuid.uuid4())
    message_envelope = {
        "id": message_id,
        "recipients": list(encrypted_keys.keys()), # Lista de quem a mensagem foi criptografada para
        "encrypted_payload": {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
        },
        "encrypted_keys": encrypted_keys
    }

    # 7. Salvar e registrar no log
    storage_manager.save_message(message_id, message_envelope)
    audit_log.log_event(f"Mensagem {message_id} enviada por '{sender_username}' para {list(encrypted_keys.keys())}")


def read_messages(recipient_username: str) -> List[Dict[str, Any]]:
    """
    Lê, descriptografa e verifica todas as mensagens destinadas a um usuário.

    Workflow:
    1.  Filtra todas as mensagens no armazenamento que são para o usuário.
    2.  Para cada mensagem:
        a. Descriptografa a chave de sessão AES com a chave privada do usuário.
        b. Usa a chave AES para descriptografar o payload da mensagem (verificando a integridade com a tag GCM).
        c. Obtém o pacote interno (payload + assinatura).
        d. Obtém a chave pública do remetente.
        e. Verifica a assinatura digital do pacote.
    3.  Retorna uma lista de mensagens decifradas e com o status da verificação da assinatura.
    """
    recipient_private_key = key_manager.get_private_key(recipient_username)
    all_messages = storage_manager.get_messages()
    decrypted_messages = []

    for msg_id, envelope in all_messages.items():
        # Verifica se o usuário é um dos destinatários da mensagem
        if recipient_username not in envelope.get("encrypted_keys", {}):
            continue

        try:
            # 1. Descriptografar a chave AES
            encrypted_aes_key_b64 = envelope["encrypted_keys"][recipient_username]
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            aes_key = crypto_service.decrypt_rsa(encrypted_aes_key, recipient_private_key)

            # 2. Descriptografar o payload
            payload_data = envelope["encrypted_payload"]
            ciphertext = base64.b64decode(payload_data["ciphertext"])
            iv = base64.b64decode(payload_data["iv"])
            tag = base64.b64decode(payload_data["tag"])
            
            inner_package_bytes = crypto_service.decrypt_aes_gcm(ciphertext, aes_key, iv, tag)
            inner_package_with_sig = json.loads(inner_package_bytes)

            # 3. Verificar a assinatura
            payload = inner_package_with_sig["payload"]
            signature_b64 = inner_package_with_sig["signature"]
            signature = base64.b64decode(signature_b64)
            
            sender_id = payload["sender_id"]
            sender_public_key = key_manager.get_public_key(sender_id)

            # Recria os dados exatos que foram assinados
            payload_str_to_verify = json.dumps(payload, sort_keys=True).encode('utf-8')
            is_signature_valid = crypto_service.verify_signature(payload_str_to_verify, signature, sender_public_key)

            # Monta a mensagem final para o usuário
            decrypted_messages.append({
                "message_id": msg_id,
                "sender": sender_id,
                "message": payload["plaintext_message"],
                "timestamp": payload["timestamp"],
                "signature_valid": is_signature_valid
            })
            
            # Log de leitura
            audit_log.log_event(f"Mensagem {msg_id} lida por '{recipient_username}'. Verificacao da assinatura: {'VALIDA' if is_signature_valid else 'INVALIDA'}")

        except Exception as e:
            # Se qualquer passo falhar (descriptografia, verificação), registra o erro
            # e continua para a próxima mensagem.
            error_msg = f"Falha ao processar mensagem {msg_id} para '{recipient_username}': {e}"
            print(error_msg)
            audit_log.log_event(error_msg)
            decrypted_messages.append({
                "message_id": msg_id,
                "error": "Nao foi possivel descriptografar ou verificar a mensagem.",
                "details": str(e)
            })

    return decrypted_messages
