"""
Este módulo centraliza todas as operações criptográficas primitivas.
Ele é "stateless", o que significa que não armazena chaves ou dados. Apenas executa
as operações com os dados que lhe são fornecidos, garantindo que a lógica
criptográfica esteja isolada e seja fácil de auditar.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- Constantes de Configuração ---
# Tamanho da chave RSA em bits. 2048 é considerado o mínimo seguro atualmente.
KEY_SIZE = 2048
# Expoente público para a geração de chaves RSA. 65537 é um valor padrão e eficiente.
PUBLIC_EXPONENT = 65537

# --- Geração de Chaves Assimétricas (RSA) ---

def generate_rsa_keys():
    """
    Gera um par de chaves RSA (privada e pública).

    Returns:
        tuple: Uma tupla contendo a chave privada e a chave pública
               (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- Serialização de Chaves (Para Armazenamento) ---

def serialize_private_key(private_key):
    """
    Serializa uma chave privada para o formato PEM para que possa ser salva em um arquivo.
    PEM é um formato de texto padrão para armazenar chaves criptográficas.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Para demo, não criptografamos o arquivo da chave
    )

def serialize_public_key(public_key):
    """
    Serializa uma chave pública para o formato PEM.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_private_key(pem_data):
    """
    Carrega uma chave privada a partir de seu formato PEM.
    """
    return serialization.load_pem_private_key(pem_data, password=None)

def deserialize_public_key(pem_data):
    """
    Carrega uma chave pública a partir de seu formato PEM.
    """
    return serialization.load_pem_public_key(pem_data)

# --- Criptografia Assimétrica (RSA-OAEP) ---

def encrypt_rsa(data: bytes, public_key) -> bytes:
    """
    Criptografa dados usando a chave pública RSA com o preenchimento OAEP.
    OAEP é o preenchimento padrão recomendado para novas aplicações, pois previne
    vários tipos de ataques. É ideal para criptografar pequenos volumes de dados,
    como uma chave de sessão AES.

    Args:
        data (bytes): Os dados a serem criptografados.
        public_key: O objeto de chave pública do destinatário.

    Returns:
        bytes: O texto cifrado.
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(ciphertext: bytes, private_key) -> bytes:
    """
    Descriptografa dados usando a chave privada RSA com o preenchimento OAEP.

    Args:
        ciphertext (bytes): O texto cifrado a ser descriptografado.
        private_key: O objeto de chave privada do destinatário.

    Returns:
        bytes: Os dados originais.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- Criptografia Simétrica (AES-GCM) ---

def generate_aes_key() -> bytes:
    """
    Gera uma chave AES de 256 bits (32 bytes) segura.
    """
    return os.urandom(32)

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> tuple:
    """
    Criptografa dados usando AES no modo GCM (Galois/Counter Mode).
    O GCM é um modo de "criptografia autenticada" (AEAD), o que significa que
    ele garante tanto a confidencialidade (sigilo) quanto a integridade e
    autenticidade dos dados.

    Args:
        plaintext (bytes): Os dados a serem criptografados.
        key (bytes): A chave AES de 32 bytes.

    Returns:
        tuple: Uma tupla contendo (ciphertext, iv, tag).
               - ciphertext: Os dados criptografados.
               - iv: O vetor de inicialização (nonce) de 12 bytes, gerado aleatoriamente.
               - tag: A tag de autenticação de 16 bytes.
    """
    iv = os.urandom(12)  # GCM usa um IV de 12 bytes
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    # A tag já está inclusa no final do ciphertext pela biblioteca, mas vamos extraí-la
    # para um armazenamento explícito, o que é uma boa prática.
    tag_length = 16  # GCM tag é de 16 bytes (128 bits)
    actual_ciphertext = ciphertext[:-tag_length]
    tag = ciphertext[-tag_length:]
    return actual_ciphertext, iv, tag

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """
    Descriptografa dados usando AES-GCM e verifica a integridade.

    Args:
        ciphertext (bytes): O texto cifrado.
        key (bytes): A chave AES.
        iv (bytes): O vetor de inicialização (nonce).
        tag (bytes): A tag de autenticação.

    Returns:
        bytes: Os dados originais (plaintext).
    
    Raises:
        cryptography.exceptions.InvalidTag: Se a descriptografia falhar
            porque a tag de autenticação não corresponde. Isso indica que os dados
            foram adulterados ou a chave está incorreta.
    """
    aesgcm = AESGCM(key)
    # A biblioteca espera que a tag esteja concatenada ao ciphertext.
    ciphertext_with_tag = ciphertext + tag
    try:
        return aesgcm.decrypt(iv, ciphertext_with_tag, None)
    except InvalidTag:
        # Relança a exceção para que a camada de serviço possa tratá-la.
        # Isso é crucial para a segurança do sistema.
        raise

# --- Funções de Hash (SHA-256) ---

def hash_sha256(data: bytes) -> bytes:
    """
    Calcula o hash SHA-256 de um conjunto de dados.
    SHA-256 é uma função de hash segura que produz uma saída de tamanho fixo (32 bytes).
    É usada para garantir a integridade dos dados.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# --- Assinatura Digital (RSA-PSS) ---

def sign_data(data: bytes, private_key) -> bytes:
    """
    Assina um conjunto de dados usando a chave privada RSA com o preenchimento PSS.
    PSS (Probabilistic Signature Scheme) é o esquema de assinatura recomendado
    para RSA, pois oferece garantias de segurança mais fortes que o antigo PKCS#1 v1.5.
    A assinatura é feita sobre o hash dos dados, não sobre os dados brutos.

    Args:
        data (bytes): Os dados a serem assinados.
        private_key: A chave privada do remetente.

    Returns:
        bytes: A assinatura digital.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verifica uma assinatura digital usando a chave pública do remetente.

    Args:
        data (bytes): Os dados originais que foram assinados.
        signature (bytes): A assinatura a ser verificada.
        public_key: A chave pública do remetente.

    Returns:
        bool: True se a assinatura for válida, False caso contrário.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
