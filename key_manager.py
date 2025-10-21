"""
Este módulo abstrai o gerenciamento de chaves dos usuários.
Ele é responsável por:
1. Criar novos pares de chaves para os usuários.
2. Salvar as chaves privadas em arquivos locais seguros (em um cenário real,
   isso seria um "vault" ou um HSM).
3. Publicar as chaves públicas no nosso "banco de dados" JSON.
4. Carregar as chaves (públicas e privadas) quando necessário.
"""

import os
import crypto_service
import storage_manager

# --- Constantes ---
KEYS_DIR = "keys"

def setup_keys_directory():
    """
    Garante que o diretório para armazenar chaves privadas exista.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

def create_user_keys(username: str):
    """
    Cria, salva e publica as chaves para um novo usuário.

    Args:
        username (str): O nome do usuário.
    
    Raises:
        FileExistsError: Se o arquivo de chave privada para o usuário já existir.
    """
    setup_keys_directory()
    private_key_path = os.path.join(KEYS_DIR, f"{username}_priv.pem")

    if os.path.exists(private_key_path):
        raise FileExistsError(f"Usuário '{username}' já possui chaves.")

    # 1. Gerar o par de chaves RSA
    private_key, public_key = crypto_service.generate_rsa_keys()

    # 2. Serializar as chaves para o formato PEM
    private_key_pem = crypto_service.serialize_private_key(private_key)
    public_key_pem = crypto_service.serialize_public_key(public_key)

    # 3. Salvar a chave privada em um arquivo local
    with open(private_key_path, "wb") as f:
        f.write(private_key_pem)
    
    # Mudar permissões do arquivo da chave privada (apenas o dono pode ler/escrever)
    os.chmod(private_key_path, 0o600)

    # 4. "Publicar" a chave pública no nosso armazenamento JSON
    storage_manager.save_public_key(username, public_key_pem.decode('utf-8'))

def get_public_key(username: str):
    """
    Obtém a chave pública de um usuário do armazenamento.

    Args:
        username (str): O nome do usuário.

    Returns:
        A chave pública como um objeto da biblioteca cryptography.
    
    Raises:
        FileNotFoundError: Se o usuário não tiver uma chave pública registrada.
    """
    public_keys = storage_manager.get_public_keys()
    public_key_pem = public_keys.get(username)

    if not public_key_pem:
        raise FileNotFoundError(f"Chave pública para o usuário '{username}' não encontrada.")
    
    return crypto_service.deserialize_public_key(public_key_pem.encode('utf-8'))

def get_private_key(username: str):
    """
    Carrega a chave privada de um usuário a partir de seu arquivo.

    Args:
        username (str): O nome do usuário.

    Returns:
        A chave privada como um objeto da biblioteca cryptography.

    Raises:
        FileNotFoundError: Se o arquivo da chave privada não for encontrado.
    """
    private_key_path = os.path.join(KEYS_DIR, f"{username}_priv.pem")
    try:
        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()
        return crypto_service.deserialize_private_key(private_key_pem)
    except FileNotFoundError:
        raise FileNotFoundError(f"Chave privada para o usuário '{username}' não encontrada. O usuário existe?")
