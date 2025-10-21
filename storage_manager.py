"""
Este módulo lida com a leitura e escrita segura em arquivos JSON no lado da API.
Ele gerencia o armazenamento de chaves públicas e envelopes de mensagens.
O uso de bloqueios de arquivo (fcntl) é mantido para garantir a integridade
dos dados em um ambiente com múltiplas requisições.
"""
import json
import fcntl
import os
from typing import Dict, Any

# --- Constantes para os nomes dos arquivos de "banco de dados" ---
DB_DIR = "data_api"
PUBLIC_KEYS_FILE = os.path.join(DB_DIR, "public_keys.json")
MESSAGES_FILE = os.path.join(DB_DIR, "messages.json")

def setup_storage():
    """Garante que o diretório de dados da API exista."""
    os.makedirs(DB_DIR, exist_ok=True)

def read_json_file(file_path: str) -> Dict[str, Any]:
    """Lê dados de um arquivo JSON de forma segura (thread-safe)."""
    setup_storage()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
            fcntl.flock(f, fcntl.LOCK_UN)
        return data
    except FileNotFoundError:
        return {}

def write_json_file(file_path: str, data: Dict[str, Any]):
    """Escreve dados em um arquivo JSON de forma segura (thread-safe)."""
    setup_storage()
    with open(file_path, 'w', encoding='utf-8') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(data, f, indent=4, ensure_ascii=False)
        fcntl.flock(f, fcntl.LOCK_UN)

# --- Funções específicas para cada "tabela" ---

def get_public_keys() -> Dict[str, str]:
    """Obtém o dicionário de chaves públicas."""
    return read_json_file(PUBLIC_KEYS_FILE)

def save_public_key(username: str, public_key_pem: str):
    """Salva ou atualiza a chave pública de um usuário."""
    keys = get_public_keys()
    keys[username] = public_key_pem
    write_json_file(PUBLIC_KEYS_FILE, keys)

def get_messages() -> Dict[str, Any]:
    """Obtém todas as mensagens armazenadas."""
    return read_json_file(MESSAGES_FILE)

def save_message(message_id: str, message_envelope: Dict[str, Any]):
    """Adiciona um novo envelope de mensagem ao arquivo."""
    messages = get_messages()
    messages[message_id] = message_envelope
    write_json_file(MESSAGES_FILE, messages)

