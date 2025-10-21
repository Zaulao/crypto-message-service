"""
Este módulo centraliza todas as operações criptográficas primitivas.
Ele é "stateless", o que significa que não armazena chaves ou dados.
É utilizado tanto pela API (para gerar chaves) quanto pelo Cliente CLI
(para assinar, criptografar e decriptografar).
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- Constantes de Configuração ---
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

# --- Geração de Chaves Assimétricas (RSA) ---

def generate_rsa_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- Serialização de Chaves (Para Armazenamento e Transmissão) ---

def serialize_private_key(private_key):
    """Serializa uma chave privada para o formato PEM."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(public_key):
    """Serializa uma chave pública para o formato PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_private_key(pem_data: bytes):
    """Carrega uma chave privada a partir de seu formato PEM."""
    return serialization.load_pem_private_key(pem_data, password=None)

def deserialize_public_key(pem_data: bytes):
    """Carrega uma chave pública a partir de seu formato PEM."""
    return serialization.load_pem_public_key(pem_data)

# --- Criptografia Assimétrica (RSA-OAEP) ---

def encrypt_rsa(data: bytes, public_key) -> bytes:
    """Criptografa dados (como uma chave AES) usando uma chave pública RSA."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(ciphertext: bytes, private_key) -> bytes:
    """Descriptografa dados usando uma chave privada RSA."""
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
    """Gera uma chave AES de 256 bits (32 bytes) segura."""
    return os.urandom(32)

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> tuple:
    """Criptografa dados usando AES-GCM, retornando (ciphertext, iv, tag)."""
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    full_ciphertext = aesgcm.encrypt(iv, plaintext, None)
    tag_length = 16
    ciphertext = full_ciphertext[:-tag_length]
    tag = full_ciphertext[-tag_length:]
    return ciphertext, iv, tag

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """Descriptografa dados AES-GCM e verifica a integridade."""
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    return aesgcm.decrypt(iv, ciphertext_with_tag, None)


# --- Funções de Hash (SHA-256) ---

def hash_sha256(data: bytes) -> bytes:
    """Calcula o hash SHA-256 de um conjunto de dados."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# --- Assinatura Digital (RSA-PSS) ---

def sign_data(data: bytes, private_key) -> bytes:
    """Assina dados usando uma chave privada RSA com preenchimento PSS."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """Verifica uma assinatura digital usando uma chave pública."""
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

