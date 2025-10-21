"""
Implementa um log de auditoria seguro e com assinatura digital.
Cada entrada no log é assinada digitalmente com uma chave RSA dedicada,
o que torna o log "tamper-evident" (à prova de adulteração). Se uma linha
for alterada, sua assinatura não será mais válida.

Este módulo precisa de seu próprio par de chaves, gerado na primeira execução.
"""
import os
import json
import base64
from datetime import datetime, timezone

import crypto_service
import storage_manager

# --- Constantes ---
LOG_FILE = os.path.join(storage_manager.DB_DIR, "audit_log.jsonl")
AUDIT_KEY_DIR = "keys"
AUDIT_PRIVATE_KEY_PATH = os.path.join(AUDIT_KEY_DIR, "audit_priv.pem")
AUDIT_PUBLIC_KEY_PATH = os.path.join(AUDIT_KEY_DIR, "audit_pub.pem")


def get_or_create_audit_keys():
    """
    Verifica se as chaves de auditoria existem. Se não, as cria.
    Carrega e retorna a chave privada de auditoria.
    """
    os.makedirs(AUDIT_KEY_DIR, exist_ok=True)
    if not os.path.exists(AUDIT_PRIVATE_KEY_PATH):
        print("Gerando novo par de chaves para o log de auditoria...")
        private_key, public_key = crypto_service.generate_rsa_keys()
        
        with open(AUDIT_PRIVATE_KEY_PATH, "wb") as f:
            f.write(crypto_service.serialize_private_key(private_key))
        os.chmod(AUDIT_PRIVATE_KEY_PATH, 0o600)

        with open(AUDIT_PUBLIC_KEY_PATH, "wb") as f:
            f.write(crypto_service.serialize_public_key(public_key))
    
    with open(AUDIT_PRIVATE_KEY_PATH, "rb") as f:
        return crypto_service.deserialize_private_key(f.read())


def log_event(event_message: str):
    """
    Cria uma entrada de log, assina e a anexa ao arquivo de log.
    O formato é JSON Lines (.jsonl), onde cada linha é um objeto JSON válido.
    """
    private_key = get_or_create_audit_keys()

    # 1. Criar o payload do log
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_message
    }
    # Usamos `sort_keys=True` para garantir uma serialização determinística,
    # o que é essencial para que a verificação da assinatura funcione.
    log_payload_str = json.dumps(log_entry, sort_keys=True)

    # 2. Assinar o payload do log
    signature = crypto_service.sign_data(log_payload_str.encode('utf-8'), private_key)

    # 3. Criar a linha final do log com a assinatura
    full_log_line = {
        "log": log_entry,
        "signature": base64.b64encode(signature).decode('utf-8')
    }

    # 4. Anexar ao arquivo de log
    storage_manager.setup_storage()
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(full_log_line) + "\n")


def read_log():
    """Lê e retorna todas as entradas do log, sem verificar assinaturas."""
    if not os.path.exists(LOG_FILE):
        return []
    
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        return [json.loads(line) for line in f]


def verify_and_read_log() -> tuple:
    """
    Lê o arquivo de log inteiro e verifica a assinatura de cada entrada.

    Returns:
        tuple: (is_valid, log_entries)
               - is_valid (bool): True se todas as entradas são válidas, False se não.
               - log_entries (list): Uma lista de entradas de log, cada uma com um
                                     campo adicional 'is_valid'.
    """
    if not os.path.exists(AUDIT_PUBLIC_KEY_PATH):
        return True, [] # Log vazio é válido

    with open(AUDIT_PUBLIC_KEY_PATH, "rb") as f:
        public_key = crypto_service.deserialize_public_key(f.read())

    if not os.path.exists(LOG_FILE):
        return True, []

    overall_valid = True
    verified_entries = []

    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entry = json.loads(line)
                log_payload = entry['log']
                signature_b64 = entry['signature']
                
                # Recria a string exata que foi assinada
                log_payload_str = json.dumps(log_payload, sort_keys=True).encode('utf-8')
                signature = base64.b64decode(signature_b64)
                
                is_entry_valid = crypto_service.verify_signature(log_payload_str, signature, public_key)
                entry['is_valid'] = is_entry_valid
                
                if not is_entry_valid:
                    overall_valid = False
                
                verified_entries.append(entry)

            except (json.JSONDecodeError, KeyError, Exception) as e:
                # Se uma linha estiver corrompida, o log inteiro é inválido
                overall_valid = False
                verified_entries.append({"error": "Linha de log inválida ou corrompida", "details": str(e), "is_valid": False})

    return overall_valid, verified_entries
