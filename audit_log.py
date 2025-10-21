"""
Implementa o log de auditoria seguro no lado da API.
A lógica é a mesma, mas as mensagens de log refletirão as novas
responsabilidades do servidor.
"""
import os
import json
import base64
from datetime import datetime, timezone

import crypto_service
import storage_manager

# --- Constantes ---
LOG_FILE = os.path.join(storage_manager.DB_DIR, "audit_log.jsonl")
AUDIT_KEY_DIR = "keys_api"
AUDIT_PRIVATE_KEY_PATH = os.path.join(AUDIT_KEY_DIR, "audit_priv.pem")
AUDIT_PUBLIC_KEY_PATH = os.path.join(AUDIT_KEY_DIR, "audit_pub.pem")


def get_or_create_audit_keys():
    """Verifica/cria e carrega as chaves de auditoria da API."""
    os.makedirs(AUDIT_KEY_DIR, exist_ok=True)
    if not os.path.exists(AUDIT_PRIVATE_KEY_PATH):
        private_key, public_key = crypto_service.generate_rsa_keys()
        
        with open(AUDIT_PRIVATE_KEY_PATH, "wb") as f:
            f.write(crypto_service.serialize_private_key(private_key))
        os.chmod(AUDIT_PRIVATE_KEY_PATH, 0o600)

        with open(AUDIT_PUBLIC_KEY_PATH, "wb") as f:
            f.write(crypto_service.serialize_public_key(public_key))
    
    with open(AUDIT_PRIVATE_KEY_PATH, "rb") as f:
        return crypto_service.deserialize_private_key(f.read())

def log_event(event_message: str):
    """Cria, assina e anexa uma entrada ao arquivo de log."""
    private_key = get_or_create_audit_keys()
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_message
    }
    log_payload_str = json.dumps(log_entry, sort_keys=True)
    signature = crypto_service.sign_data(log_payload_str.encode('utf-8'), private_key)
    full_log_line = {
        "log": log_entry,
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    storage_manager.setup_storage()
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(full_log_line) + "\n")

def verify_and_read_log() -> tuple:
    """Lê e verifica a assinatura de cada entrada do log."""
    if not os.path.exists(AUDIT_PUBLIC_KEY_PATH):
        return True, []

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
                log_payload_str = json.dumps(log_payload, sort_keys=True).encode('utf-8')
                signature = base64.b64decode(signature_b64)
                is_entry_valid = crypto_service.verify_signature(log_payload_str, signature, public_key)
                entry['is_valid'] = is_entry_valid
                if not is_entry_valid:
                    overall_valid = False
                verified_entries.append(entry)
            except Exception as e:
                overall_valid = False
                verified_entries.append({"error": "Linha de log invalida", "details": str(e), "is_valid": False})
    return overall_valid, verified_entries

