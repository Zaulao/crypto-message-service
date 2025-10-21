"""
Este módulo lida com a leitura e escrita segura em arquivos JSON.
Para um ambiente de demonstração, ele substitui um banco de dados.
A principal característica aqui é o uso de bloqueios de arquivo (file locks)
para evitar "race conditions" - situações em que múltiplas requisições
tentam modificar o mesmo arquivo simultaneamente, o que poderia corromper
os dados.

Nota: fcntl é específico para sistemas baseados em Unix (Linux, macOS).
Para um sistema compatível com Windows, seria necessária uma biblioteca
diferente, como 'portalocker'.
"""
import json
import fcntl
import os
from typing import Dict, Any

# --- Constantes para os nomes dos arquivos de "banco de dados" ---
DB_DIR = "data"
PUBLIC_KEYS_FILE = os.path.join(DB_DIR, "public_keys.json")
MESSAGES_FILE = os.path.join(DB_DIR, "messages.json")

def setup_storage():
    """
    Garante que o diretório de dados exista.
    """
    os.makedirs(DB_DIR, exist_ok=True)


def read_json_file(file_path: str) -> Dict[str, Any]:
    """
    Lê dados de um arquivo JSON de forma segura (thread-safe).

    Usa um bloqueio compartilhado (LOCK_SH), o que permite que múltiplos
    processos leiam o arquivo ao mesmo tempo, mas impede que qualquer
    processo escreva nele durante a leitura.

    Args:
        file_path (str): O caminho para o arquivo JSON.

    Returns:
        dict: O conteúdo do arquivo como um dicionário Python. Retorna um
              dicionário vazio se o arquivo não existir.
    """
    setup_storage()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Adquire um bloqueio compartilhado
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {} # Retorna um dict vazio se o arquivo estiver vazio ou corrompido
            # Libera o bloqueio
            fcntl.flock(f, fcntl.LOCK_UN)
        return data
    except FileNotFoundError:
        return {}


def write_json_file(file_path: str, data: Dict[str, Any]):
    """
    Escreve dados em um arquivo JSON de forma segura (thread-safe).

    Usa um bloqueio exclusivo (LOCK_EX), que impede que qualquer outro
    processo leia ou escreva no arquivo enquanto a operação de escrita
    está em andamento. Isso é crucial para manter a integridade do arquivo.

    Args:
        file_path (str): O caminho para o arquivo JSON.
        data (dict): O dicionário Python a ser salvo.
    """
    setup_storage()
    with open(file_path, 'w', encoding='utf-8') as f:
        # Adquire um bloqueio exclusivo
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(data, f, indent=4, ensure_ascii=False)
        # Libera o bloqueio
        fcntl.flock(f, fcntl.LOCK_UN)

# --- Funções específicas para cada "tabela" ---

def get_public_keys() -> Dict[str, str]:
    """
    Obtém o dicionário de chaves públicas.
    Chave: username, Valor: chave pública em formato PEM.
    """
    return read_json_file(PUBLIC_KEYS_FILE)


def save_public_key(username: str, public_key_pem: str):
    """
    Salva ou atualiza a chave pública de um usuário.
    """
    keys = get_public_keys()
    keys[username] = public_key_pem
    write_json_file(PUBLIC_KEYS_FILE, keys)


def get_messages() -> Dict[str, Any]:
    """
    Obtém todas as mensagens armazenadas.
    """
    return read_json_file(MESSAGES_FILE)


def save_message(message_id: str, message_envelope: Dict[str, Any]):
    """
    Adiciona um novo envelope de mensagem ao arquivo.
    """
    messages = get_messages()
    messages[message_id] = message_envelope
    write_json_file(MESSAGES_FILE, messages)
