from fastapi import FastAPI, HTTPException, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from fastapi_mcp import FastApiMCP
from fastapi.security import APIKeyHeader
import uvicorn
import notion_hex
from config import AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT_NAME, AZURE_OPENAI_API_VERSION, API_KEY, NOTION_API_TOKEN, NOTION_CLIENT_ID, NOTION_CLIENT_SECRET, NOTION_REDIRECT_URI
import openai
import json
import os
import secrets
from typing import Dict, Any, Optional
from starlette.middleware.sessions import SessionMiddleware
import requests

app = FastAPI(title="Notion MCP API", description="Servidor MCP para interactuar con la API de Notion usando OpenAI y OAuth")

# Configuración de middlewares
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(16))

# Configuración de OAuth
AUTH_URL = "https://api.notion.com/v1/oauth/authorize"
TOKEN_URL = "https://api.notion.com/v1/oauth/token"
API_VERSION = "2022-06-28"

# Inicialización de NotionRestAdapter con manejo de excepciones
try:
    notion_client = notion_hex.NotionRestAdapter()
except Exception as e:
    raise ValueError(f"Error al inicializar NotionRestAdapter: {str(e)}")

# Verificación de credenciales de Azure OpenAI
if not all([AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT_NAME, AZURE_OPENAI_API_VERSION]):
    raise ValueError("Faltan variables de entorno para Azure OpenAI: AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT_NAME, o AZURE_OPENAI_API_VERSION")

# Configuración del cliente de Azure OpenAI
try:
    openai_client = openai.AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_KEY,
        api_version=AZURE_OPENAI_API_VERSION
    )
except Exception as e:
    raise ValueError(f"Error al inicializar el cliente de Azure OpenAI: {str(e)}")

# Autenticación con API Key (respaldo)
api_key_header = APIKeyHeader(name="X-API-Key")
async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != os.getenv("API_KEY"):
        raise HTTPException(status_code=401, detail="Clave API inválida")

# Obtener token de la sesión
async def get_token(request: Request):
    token = request.session.get("notion_token")
    if not token:
        raise HTTPException(status_code=401, detail="No autorizado. Por favor inicie sesión.")
    return token

def parse_notion_command2(prompt: str) -> Dict[str, Any]:
    """Azure OpenAI para parsear comandos en lenguaje natural a parámetros de la API de Notion"""
    try:
        response = openai_client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT_NAME,
            messages=[
                {
                    "role": "system",
                    "content": """Eres un asistente que parsea comandos en español o inglés a comandos de la API de Notion. Devuelve un objeto JSON con 'action' (uno de: GET_DATABASE, QUERY_DATABASE, CREATE_PAGE, RETRIEVE_PAGE, UPDATE_PAGE, RETRIEVE_BLOCK, APPEND_BLOCK_CHILDREN, UPDATE_BLOCK, DELETE_BLOCK, SEARCH, GET_USERS, GET_USER, GET_ME, CREATE_COMMENT, GET_COMMENTS, CREATE_DATABASE) y 'params' (un diccionario con los parámetros requeridos como cadenas simples, sin anidar diccionarios). Ejemplo: {"action": "CREATE_PAGE", "params": {"database_id": "123", "title": "Nueva Página"}}"""
                },
                {"role": "user", "content": prompt}
            ]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en Azure OpenAI: {str(e)}")

def parse_notion_command(prompt: str) -> Dict[str, Any]:
    """Usa Azure OpenAI para parsear comandos en español o inglés a parámetros de la API de Notion"""
    try:
        response = openai_client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT_NAME,
            messages=[
                {
                    "role": "system",
                    "content": """Eres un asistente que parsea comandos en español o inglés a comandos de la API de Notion. Devuelve un objeto JSON con 'action' (uno de: GET_DATABASE, QUERY_DATABASE, CREATE_PAGE, RETRIEVE_PAGE, UPDATE_PAGE, RETRIEVE_BLOCK, APPEND_BLOCK_CHILDREN, UPDATE_BLOCK, DELETE_BLOCK, SEARCH, GET_USERS, GET_USER, GET_ME, CREATE_COMMENT, GET_COMMENTS, CREATE_DATABASE) y 'params' (un diccionario con los parámetros requeridos como cadenas simples, sin anidar diccionarios, excepto para 'filter' en QUERY_DATABASE, que debe ser un objeto JSON válido como {\"filter\": {\"property\": \"Estado\", \"status\": {\"equals\": \"En progreso\"}}}). Usa 'parent_id' para especificar el ID de una base de datos o página en CREATE_PAGE, no 'database_id'. Ejemplo 1: {\"action\": \"CREATE_PAGE\", \"params\": {\"parent_id\": \"123\", \"title\": \"Nueva Página\"}}. Ejemplo 2: {\"action\": \"QUERY_DATABASE\", \"params\": {\"database_id\": \"123\", \"filter\": {\"filter\": {\"property\": \"Estado\", \"status\": {\"equals\": \"En progreso\"}}}}}. Asegúrate de que los IDs sean cadenas alfanuméricas válidas (por ejemplo, UUIDs como '123e4567-e89b-12d3-a456-426614174000')."""
                },
                {"role": "user", "content": prompt}
            ]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en Azure OpenAI: {str(e)}")

def make_notion_request(command_json: Dict[str, Any], token: str) -> Dict[str, Any]:
    """Realiza una petición a la API de Notion usando requests basado en el JSON devuelto por C++"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json"
    }

    url = command_json.get("url")
    method = command_json.get("method")
    data = command_json.get("data")

    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=data)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, data=data)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers)

        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=getattr(e.response, 'status_code', 400), detail=str(e))

@app.get("/")
async def index():
    return {"message": "Bienvenido a la API de integración con Notion", "login_url": "/login"}

@app.get("/login")
async def login(request: Request):
    state = secrets.token_hex(16)
    request.session["oauth_state"] = state

    auth_params = {
        "client_id": NOTION_CLIENT_ID,
        "redirect_uri": NOTION_REDIRECT_URI,
        "response_type": "code",
        "state": state,
        "owner": "user"
    }

    auth_url = f"{AUTH_URL}?client_id={auth_params['client_id']}&redirect_uri={auth_params['redirect_uri']}&response_type={auth_params['response_type']}&state={auth_params['state']}&owner={auth_params['owner']}"
    print(f"Generated auth URL: {auth_url}")  # Depuración
    return RedirectResponse(auth_url, status_code=303)  # Usar 303 para forzar redirección

@app.get("/callback")
async def callback(request: Request, code: str, state: Optional[str] = None):
    session_state = request.session.get("oauth_state")
    if not state or state != session_state:
        raise HTTPException(status_code=403, detail="Estado inválido. Posible ataque CSRF.")

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": NOTION_REDIRECT_URI
    }

    response = requests.post(
        TOKEN_URL,
        json=token_data,
        auth=(NOTION_CLIENT_ID, NOTION_CLIENT_SECRET),
        headers={"Content-Type": "application/json"}
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener el token: {response.text}"
        )

    token_info = response.json()
    access_token = token_info.get("access_token")
    request.session["notion_token"] = access_token

    return {"message": "Conexión exitosa con Notion", "token_obtained": True}

@app.get("/logout")
async def logout(request: Request):
    if "notion_token" in request.session:
        del request.session["notion_token"]
    return {"message": "Sesión cerrada exitosamente"}

@app.post("/notion/chat", operation_id="process_notion_chat", dependencies=[Depends(get_token)])
async def process_notion_chat(command: str = Form(...), token: str = Depends(get_token)):
    print(f"Token recibido: {token}")  # Depuración
    try:
        parsed_command = parse_notion_command(command)
        print("Parsed command:", parsed_command)
        action = getattr(notion_hex.NotionAction, parsed_command["action"])
        params = parsed_command["params"]
        print("Params passed to execute:", params)
        execute_params = {
            "action": action,
            "params": params,
            "token": token
        }
        print(f"Execute params: {execute_params}")  # Depuración adicional
        command_json = json.loads(notion_client.execute(execute_params))
        result = make_notion_request(command_json, token)
        print("Raw result from execute:", result)
        return result
    except json.JSONDecodeError as e:
        print("JSON Decode Error:", result)
        raise HTTPException(status_code=400, detail=f"Error parsing JSON body: {str(e)}")
    except Exception as e:
        print("Execute exception:", str(e))
        raise HTTPException(status_code=400, detail=f"Error procesando el comando: {str(e)}")

@app.get("/notion/database/{database_id}", operation_id="get_notion_database", dependencies=[Depends(get_token)])
async def get_notion_database(database_id: str, token: str = Depends(get_token)):
    """Obtiene una base de datos de Notion por ID"""
    try:
        command = {"action": notion_hex.NotionAction.GET_DATABASE, "params": {"database_id": database_id}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/notion/database/{database_id}/query", operation_id="query_notion_database", dependencies=[Depends(get_token)])
async def query_notion_database(database_id: str, filter: str = Form(default="{}"), token: str = Depends(get_token)):
    """Consulta una base de datos de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.QUERY_DATABASE, "params": {"database_id": database_id, "filter": filter}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/notion/page/{database_id}", operation_id="create_notion_page", dependencies=[Depends(get_token)])
async def create_notion_page(database_id: str, title: str = Form(...), token: str = Depends(get_token)):
    """Crea una nueva página en una base de datos de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.CREATE_PAGE, "params": {"parent_id": database_id, "title": title}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/notion/page/{page_id}", operation_id="retrieve_notion_page", dependencies=[Depends(get_token)])
async def retrieve_notion_page(page_id: str, token: str = Depends(get_token)):
    """Obtiene una página de Notion por ID"""
    try:
        command = {"action": notion_hex.NotionAction.RETRIEVE_PAGE, "params": {"page_id": page_id}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.patch("/notion/page/{page_id}", operation_id="update_notion_page", dependencies=[Depends(get_token)])
async def update_notion_page(page_id: str, properties: str = Form(...), token: str = Depends(get_token)):
    """Actualiza una página de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.UPDATE_PAGE, "params": {"page_id": page_id, "properties": properties}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/notion/block/{block_id}", operation_id="retrieve_notion_block", dependencies=[Depends(get_token)])
async def retrieve_notion_block(block_id: str, token: str = Depends(get_token)):
    """Obtiene un bloque de Notion por ID"""
    try:
        command = {"action": notion_hex.NotionAction.RETRIEVE_BLOCK, "params": {"block_id": block_id}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.patch("/notion/block/{block_id}/children", operation_id="append_notion_block_children", dependencies=[Depends(get_token)])
async def append_notion_block_children(block_id: str, children: str = Form(...), token: str = Depends(get_token)):
    """Agrega hijos a un bloque de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.APPEND_BLOCK_CHILDREN, "params": {"block_id": block_id, "children": children}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.patch("/notion/block/{block_id}", operation_id="update_notion_block", dependencies=[Depends(get_token)])
async def update_notion_block(block_id: str, block_data: str = Form(...), token: str = Depends(get_token)):
    """Actualiza un bloque de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.UPDATE_BLOCK, "params": {"block_id": block_id, "block_data": block_data}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/notion/block/{block_id}", operation_id="delete_notion_block", dependencies=[Depends(get_token)])
async def delete_notion_block(block_id: str, token: str = Depends(get_token)):
    """Elimina un bloque de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.DELETE_BLOCK, "params": {"block_id": block_id}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/notion/search", operation_id="search_notion", dependencies=[Depends(get_token)])
async def search_notion(query: str = Form(...), token: str = Depends(get_token)):
    """Busca contenido en Notion"""
    try:
        command = {"action": notion_hex.NotionAction.SEARCH, "params": {"query": query}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/notion/users", operation_id="get_notion_users", dependencies=[Depends(get_token)])
async def get_notion_users(token: str = Depends(get_token)):
    """Obtiene todos los usuarios de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.GET_USERS, "params": {}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/notion/users/{user_id}", operation_id="get_notion_user", dependencies=[Depends(get_token)])
async def get_notion_user(user_id: str, token: str = Depends(get_token)):
    """Obtiene un usuario de Notion por ID"""
    try:
        command = {"action": notion_hex.NotionAction.GET_USER, "params": {"user_id": user_id}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/notion/users/me", operation_id="get_notion_me", dependencies=[Depends(get_token)])
async def get_notion_me(token: str = Depends(get_token)):
    """Obtiene el usuario actual de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.GET_ME, "params": {}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/notion/comments", operation_id="create_notion_comment", dependencies=[Depends(get_token)])
async def create_notion_comment(comment_data: str = Form(...), token: str = Depends(get_token)):
    """Crea un comentario en Notion"""
    try:
        command = {"action": notion_hex.NotionAction.CREATE_COMMENT, "params": {"comment_data": comment_data}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/notion/comments", operation_id="get_notion_comments", dependencies=[Depends(get_token)])
async def get_notion_comments(page_id: str, token: str = Depends(get_token)):
    """Obtiene los comentarios de una página de Notion"""
    try:
        command = {"action": notion_hex.NotionAction.GET_COMMENTS, "params": {"page_id": page_id}, "token": token}
        command_json = json.loads(notion_client.execute(command))
        result = make_notion_request(command_json, token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

mcp = FastApiMCP(
    app,
    name="Notion MCP Server",
    description="Servidor MCP para interactuar con la API de Notion usando OpenAI y OAuth",
    describe_all_responses=True,
    describe_full_response_schema=True
)
mcp.mount()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)