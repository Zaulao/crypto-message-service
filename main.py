"""
Este arquivo define a interface da aplicação usando o framework FastAPI.
Ele expõe endpoints HTTP para cada uma das funcionalidades principais:
- Criar um usuário (gerar suas chaves)
- Enviar uma mensagem
- Ler as mensagens de um usuário
- Consultar e verificar o log de auditoria

FastAPI gera automaticamente uma documentação interativa (Swagger UI),
o que torna a demonstração da API muito mais fácil e visual.
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

# Importa os módulos de serviço da nossa aplicação
import key_manager
import message_service
import audit_log
import storage_manager

# Inicializa a aplicação FastAPI
app = FastAPI(
    title="Sistema Seguro de Troca de Mensagens",
    description="Uma API para demonstrar criptografia híbrida, assinaturas digitais e logs de auditoria.",
    version="1.0.0",
)

# --- Modelos de Dados (Pydantic) ---
# Pydantic força a validação dos tipos de dados para requisições e respostas,
# tornando a API mais robusta.

class CreateUserRequest(BaseModel):
    username: str

class UserResponse(BaseModel):
    status: str
    username: str

class SendMessageRequest(BaseModel):
    sender: str
    recipients: List[str]
    message: str

class StatusResponse(BaseModel):
    status: str
    details: Optional[str] = None

class ReadMessageResponse(BaseModel):
    message_id: str
    sender: Optional[str] = None
    message: Optional[str] = None
    timestamp: Optional[str] = None
    signature_valid: Optional[bool] = None
    error: Optional[str] = None

class AuditLogEntry(BaseModel):
    log: Dict[str, Any]
    signature: str
    is_valid: Optional[bool] = None

class AuditLogResponse(BaseModel):
    log_is_valid: bool
    log: List[AuditLogEntry]


@app.on_event("startup")
async def startup_event():
    """
    Função executada na inicialização da API.
    Garante que os diretórios e chaves de auditoria existam.
    """
    storage_manager.setup_storage()
    audit_log.get_or_create_audit_keys()
    print("Sistema iniciado e pronto para operar.")


# --- Endpoints da API ---

@app.post("/create-user",
          response_model=UserResponse,
          status_code=status.HTTP_201_CREATED,
          summary="Cria um novo usuário e seu par de chaves")
async def create_user(request: CreateUserRequest):
    """
    Gera um par de chaves RSA para um novo usuário.
    - A **chave privada** é salva localmente no servidor (no diretório `keys/`).
    - A **chave pública** é armazenada no "banco de dados" (`data/public_keys.json`).
    """
    try:
        key_manager.create_user_keys(request.username)
        audit_log.log_event(f"Usuario '{request.username}' criado com sucesso.")
        return {"status": "success", "username": request.username}
    except FileExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Usuario '{request.username}' já existe."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro inesperado ao criar usuario: {e}"
        )

@app.post("/send-message",
          response_model=StatusResponse,
          summary="Envia uma mensagem criptografada e assinada")
async def send_message_endpoint(request: SendMessageRequest):
    """
    Implementa o fluxo completo de envio de mensagem segura:
    1.  A mensagem é assinada com a chave privada do **remetente**.
    2.  A mensagem assinada é criptografada com uma chave **AES** de uso único.
    3.  A chave AES é criptografada com a chave pública **RSA** de cada **destinatário**.
    4.  O pacote final (envelope) é salvo.
    """
    try:
        message_service.send_message(
            sender_username=request.sender,
            recipient_usernames=request.recipients,
            plaintext_message=request.message
        )
        return {"status": "message sent"}
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro inesperado ao enviar mensagem: {e}"
        )


@app.get("/messages/{username}",
         response_model=List[ReadMessageResponse],
         summary="Lê todas as mensagens de um usuário")
async def read_messages_endpoint(username: str):
    """
    Busca, descriptografa e verifica todas as mensagens destinadas a um usuário.
    1.  Usa a chave privada do **usuário** para descriptografar a chave de sessão AES.
    2.  Usa a chave AES para descriptografar a mensagem.
    3.  Usa a chave pública do **remetente** para verificar a assinatura digital.
    """
    try:
        messages = message_service.read_messages(recipient_username=username)
        return messages
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro inesperado ao ler mensagens: {e}"
        )

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
        if verify:
            is_valid, log_entries = audit_log.verify_and_read_log()
            return {"log_is_valid": is_valid, "log": log_entries}
        else:
            log_entries = audit_log.read_log()
            return {"log_is_valid": True, "log": log_entries} # Assume válido se não verificado
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar o log de auditoria: {e}"
        )
