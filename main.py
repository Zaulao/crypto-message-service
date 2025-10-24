"""
Esta API agora tem responsabilidades limitadas e bem definidas:
1.  Gerenciar um diretório de chaves públicas.
2.  Agir como uma "caixa de correio" para armazenar e entregar envelopes de
    mensagens criptografadas, sem ter acesso ao seu conteúdo.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uuid

import crypto_service
import storage_manager
import audit_log

# --- Modelos de Dados (Pydantic) ---

class CreateUserRequest(BaseModel):
    username: str

class CreateUserResponse(BaseModel):
    username: str
    private_key_pem: str # Retorna a chave privada para o cliente
    public_key_pem: str

class PublicKeyResponse(BaseModel):
    username: str
    public_key_pem: str

class MessageEnvelope(BaseModel):
    # O cliente envia este envelope completo para a API
    sender: str
    recipients: List[str]
    encrypted_payload: Dict[str, str]
    encrypted_keys: Dict[str, str]

class StoredMessageResponse(BaseModel):
    id: str
    envelope: MessageEnvelope

class AuditLogEntry(BaseModel):
    log: Dict[str, Any]
    signature: str
    is_valid: Optional[bool] = None

class AuditLogResponse(BaseModel):
    log_is_valid: bool
    log: List[AuditLogEntry]

# --- Inicialização da API ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Inicializa os diretórios da API e as chaves de auditoria."""
    storage_manager.setup_storage()
    audit_log.get_or_create_audit_keys()
    print("API do Servidor iniciada.")
    yield

app = FastAPI(
    title="API do Servidor de Mensagens Seguras",
    description="Servidor 'Zero-Trust' que gerencia chaves públicas e armazena mensagens criptografadas.",
    version="1.0.0",
    lifespan=lifespan,
)


# --- Endpoints da API ---

@app.post("/users",
          response_model=CreateUserResponse,
          status_code=status.HTTP_201_CREATED,
          summary="Cria um novo usuário e retorna seu par de chaves")
async def create_user(request: CreateUserRequest):
    """
    1.  Verifica se o usuário já existe.
    2.  Gera um novo par de chaves RSA.
    3.  Salva a chave PÚBLICA no armazenamento do servidor.
    4.  Retorna AMBAS as chaves (privada e pública) para o cliente.
        A API NÃO armazena a chave privada.
    """
    if request.username in storage_manager.get_public_keys():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Usuário '{request.username}' já existe."
        )

    private_key, public_key = crypto_service.generate_rsa_keys()
    private_key_pem = crypto_service.serialize_private_key(private_key).decode('utf-8')
    public_key_pem = crypto_service.serialize_public_key(public_key).decode('utf-8')

    storage_manager.save_public_key(request.username, public_key_pem)
    audit_log.log_event(f"Usuario '{request.username}' criado. Chave publica registrada.")

    return {
        "username": request.username,
        "private_key_pem": private_key_pem,
        "public_key_pem": public_key_pem
    }


@app.get("/keys/{username}",
         response_model=PublicKeyResponse,
         summary="Obtém a chave pública de um usuário")
async def get_public_key(username: str):
    """
    Permite que clientes busquem a chave pública de outros usuários para poderem
    enviar mensagens a eles.
    """
    keys = storage_manager.get_public_keys()
    if username not in keys:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario não encontrado.")
    
    audit_log.log_event(f"Chave publica para '{username}' solicitada.")
    return {"username": username, "public_key_pem": keys[username]}


@app.post("/messages",
          status_code=status.HTTP_201_CREATED,
          summary="Recebe e armazena um envelope de mensagem selado")
async def store_message(envelope: MessageEnvelope):
    """
    Este endpoint simplesmente recebe um envelope de mensagem que já foi
    totalmente criptografado e assinado no cliente. A API atua como uma
    caixa de correio, armazenando o envelope sem inspecioná-lo.
    """
    message_id = str(uuid.uuid4())
    storage_manager.save_message(message_id, envelope.model_dump())
    audit_log.log_event(f"Mensagem {message_id} de '{envelope.sender}' armazenada para {envelope.recipients}.")
    return {"status": "message stored", "message_id": message_id}


@app.get("/messages/{username}",
         response_model=List[StoredMessageResponse],
         summary="Busca todos os envelopes de mensagens para um usuário")
async def get_messages_for_user(username: str):
    """
    Retorna todos os envelopes de mensagens brutos onde o `username` está
    listado como um dos destinatários. A decriptografia ocorrerá no cliente.
    """
    all_messages = storage_manager.get_messages()
    user_messages = []
    for msg_id, envelope_data in all_messages.items():
        # A Pydantic fará a validação aqui
        envelope = MessageEnvelope(**envelope_data)
        if username in envelope.recipients:
            user_messages.append({"id": msg_id, "envelope": envelope})
    
    audit_log.log_event(f"Mensagens solicitadas por '{username}'. {len(user_messages)} encontradas.")
    return user_messages

@app.get("/audit-log",
         response_model=AuditLogResponse,
         summary="Consulta e verifica o log de auditoria")
async def get_audit_log(verify: bool = True):
    """
    Retorna o log de auditoria. Se `verify=true`, a integridade de cada
    entrada do log é verificada usando a chave pública de auditoria antes
    de ser retornada.
    """
    try:
        is_valid, log_entries = audit_log.verify_and_read_log()
        return {"log_is_valid": is_valid, "log": log_entries}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar o log de auditoria: {e}"
        )