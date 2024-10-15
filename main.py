import secrets
import sqlite3
import jwt
import logging
from datetime import datetime, timedelta
from typing import Optional, Union
from contextlib import closing
import requests
from fastapi import (
    FastAPI, Request, Form, Depends, HTTPException, status, Query
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jwt import ExpiredSignatureError, InvalidTokenError
from auth import create_access_token, verify_token
from database import get_db, init_db, hash_password, verify_password
from contextlib import asynccontextmanager

# Configuración del logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Iniciar la aplicación
app = FastAPI()

# Configurar archivos estáticos y plantillas
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

IPINFO_TOKEN = "1adea7cad9f59d"
# Inicializar la base de datos al arrancar
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicialización de la base de datos al inicio de la aplicación
    print("Inicializando la base de datos...")
    init_db()  # Llama a tu función de inicialización de la BBDD aquí

    yield  

    print("Aplicación cerrada.")

def load_secret_key():
    """Carga la clave secreta desde un archivo."""
    try:
        with open("secret_key.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        # Si el archivo no existe, generamos una nueva clave y la guardamos
        secret_key = secrets.token_hex(32)
        with open("secret_key.txt", "w") as f:
            f.write(secret_key)
        return secret_key

SECRET_KEY = load_secret_key()
ALGORITHM = "HS256"

def create_access_token(data: dict, secret_key: str, expires_delta: timedelta = None) -> str:
    """Crea un token JWT."""
    to_encode = data.copy()
    
    # Establecer la fecha de expiración del token
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})

    # Generar y retornar el token JWT
    return jwt.encode(to_encode, secret_key, algorithm="HS256")

logging.info(f"SECRET_KEY cargada: {SECRET_KEY}")

def verify_token(token: str, secret_key: str):
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except (ExpiredSignatureError, InvalidTokenError):
        return None

###  Habilitar solo para pruebas
    @app.post("/login")
    async def login(username: str = Form(...), password: str = Form(...)):
        if username == "testuser" and password == "testpass":
            return {"access_token": "your_token"}
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
###

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    token = request.cookies.get("access_token")
    user_authenticated = False

    if token and verify_token(token, SECRET_KEY):  
        user_authenticated = True

    return templates.TemplateResponse("base.html", {
        "request": request,
        "title": "Inicio",
        "user_authenticated": user_authenticated,
    })


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    """Muestra el formulario de registro."""
    return templates.TemplateResponse("register.html", {"request": request})
@app.post("/register")
def register_user(
    username: str = Form(...),
    password: str = Form(...),
    db: sqlite3.Connection = Depends(get_db)
):
    """Registra un nuevo usuario."""
    hashed_password = hash_password(password)
    try:
        db.execute(
            "INSERT INTO users (username, hashed_password) VALUES (?, ?)",
            (username, hashed_password)
        )
        db.commit()
        return RedirectResponse(url="/login", status_code=302)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    """Formulario de inicio de sesión."""
    return templates.TemplateResponse("login.html", {"request": request, "title": "Iniciar sesión"})

@app.post("/login")
def login(
    request: Request,
    username: str = Form(...), 
    password: str = Form(...), 
    db: sqlite3.Connection = Depends(get_db)
):
    """Inicio de sesión del usuario."""
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    
    if not user or not verify_password(password, user["hashed_password"]):

        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error_message": "Credenciales inválidas", "title": "Iniciar sesión"}
        )

    # Crear el token JWT con la clave secreta cargada
    token = create_access_token({"sub": username}, SECRET_KEY)

    # Guardar el token en las cookies
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/dashboard")
def dashboard(request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Ruta para acceder al Dashboard."""
    logger.info("Accediendo al Dashboard...")
    token = request.cookies.get("access_token")
    if not token or not verify_token(token, SECRET_KEY):
        logger.warning("Token inválido. Redirigiendo a /login")
        return RedirectResponse("/login")

    history = db.execute("SELECT * FROM ip_info").fetchall()
    logger.info(f"{len(history)} registros encontrados en el historial.")

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "history": [dict(row) for row in history]
    })


@app.get("/filter-history")
def filter_history(
    request: Request,
    country_code: Optional[str] = Query(None),
    is_tor: Optional[str] = Query(None),  
    is_cloud: Optional[str] = Query(None),  
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    db: sqlite3.Connection = Depends(get_db)
):
    token = request.cookies.get("access_token")
    if not token or not verify_token(token, SECRET_KEY):
        return RedirectResponse("/login")

    query = "SELECT * FROM ip_info WHERE 1=1"
    params = []

    if country_code:
        query += " AND country_code = ?"
        params.append(country_code)

    if is_tor in ["0", "1"]:  # Validar solo si el valor es '0' o '1'
        query += " AND is_tor = ?"
        params.append(int(is_tor))

    if is_cloud in ["0", "1"]:  # Validar solo si el valor es '0' o '1'
        query += " AND is_cloud_provider = ?"
        params.append(int(is_cloud))

    if start_date and end_date:
        try:
            # Validar formato de fecha
            start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")
            end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")
            query += " AND last_checked BETWEEN ? AND ?"
            params.extend([start_date, end_date])
        except ValueError:
            return {"error": "Formato de fecha inválido. Use YYYY-MM-DD."}

    # Ejecutar la consulta con los parámetros
    history = db.execute(query, params).fetchall()
    history_data = [dict(row) for row in history]

    return templates.TemplateResponse("filter.html", {
        "request": request,
        "history": history_data
    })






@app.post("/add-important-ip")
def add_important_ip(
    request: Request,  # El argumento sin valor por defecto debe ir antes
    ip: str = Form(...),  # Este tiene valor por defecto, debe ir después
    db: sqlite3.Connection = Depends(get_db)
):
    """Marca una IP como importante."""
    token = request.cookies.get("access_token")
    if not token or not verify_token(token, SECRET_KEY):
        return RedirectResponse("/login", status_code=302)

    existing_ip = db.execute("SELECT * FROM ip_info WHERE ip = ?", (ip,)).fetchone()
    if not existing_ip:
        raise HTTPException(status_code=404, detail="La IP no existe en la base de datos")

    db.execute("UPDATE ip_info SET is_important = 1 WHERE ip = ?", (ip,))
    db.commit()

    return RedirectResponse("/important-ips", status_code=303)



@app.get("/important-ips")
def important_ips(request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Muestra las IPs marcadas como importantes."""
    logger.info("Accediendo a la lista de IPs importantes...")
    token = request.cookies.get("access_token")
    if not token or not verify_token(token, SECRET_KEY):
        logger.warning("Acceso denegado. Redirigiendo a /login")
        return RedirectResponse("/login")

    important_ips = db.execute("SELECT * FROM ip_info WHERE is_important = 1").fetchall()
    logger.info(f"{len(important_ips)} IPs importantes encontradas.")

    return templates.TemplateResponse("important_ips.html", {
        "request": request,
        "important_ips": [dict(row) for row in important_ips]
    })



@app.get("/logout")
def logout(request: Request):
    """Elimina el token y redirige al login."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key="access_token")  
    return response


def is_malicious_ip_virustotal(ip: str) -> bool:
    """Consulta si una IP es maliciosa usando la API de VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": "cb4f61dd4ba65a919b520446f696b18097509fa9dda293817eb070df6000e92d"
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
        
        # La IP es maliciosa si al menos un motor de análisis la marca como maliciosa
        return last_analysis_stats["malicious"] > 0
    else:
        print(f"Error en la API de VirusTotal: {response.status_code}")
        return False

def get_ip_details(ip: str) -> dict:
    """Consulta información de la IP usando ipinfo.io y otras fuentes."""
    url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    response = requests.get(url)

    if response.status_code != 200:
        raise HTTPException(status_code=404, detail="No se pudo obtener la información de la IP")

    data = response.json()

    ip_info = {
        "ip": ip,
        "hostname": data.get("hostname", "N/A"),
        "country_code": data.get("country", "N/A"),
        "region": data.get("region", "N/A"),
        "city": data.get("city", "N/A"),
        "loc": data.get("loc", "N/A"),
        "org": data.get("org", "N/A"),
        "is_cloud_provider": is_cloud_provider(data.get("org", "")),
        "is_bot": is_known_bot(data.get("org", "")),
        "is_tor": is_tor_ip(ip),  # Llamada a la función para verificar TOR
        "is_vpn": is_vpn_ip(ip),  # Llamada a la función para verificar VPN
        "is_malicious": is_malicious_ip_virustotal(ip),  # Verificación de VirusTotal
        "last_checked": datetime.utcnow()
    }
    return ip_info


@app.get("/ip-info", response_class=HTMLResponse)
def get_ip_info(
    request: Request, 
    db: sqlite3.Connection = Depends(get_db), 
    ips: str = Query(...)
):
    """Consulta información de múltiples IPs y las muestra en el dashboard."""
    try:
        # Obtener el token desde las cookies
        token = request.cookies.get("access_token")
        user_info = verify_token(token, SECRET_KEY)

        if not user_info:
            raise HTTPException(status_code=401, detail="No autenticado")

        # Extraer el nombre del usuario
        username = user_info.get("sub", "Desconocido")

        # Separar las IPs enviadas en la query string
        ip_list = [ip.strip() for ip in ips.split(",")]

        results = []
        for ip in ip_list:
            ip_data = db.execute("SELECT * FROM ip_info WHERE ip = ?", (ip,)).fetchone()

            if ip_data:
                last_checked = datetime.strptime(ip_data['last_checked'], "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_checked < timedelta(hours=12):
                    results.append(dict(ip_data))
                    continue

            ip_info = get_ip_details(ip)
            
            # Guardar la IP y el usuario que la consultó
            db.execute("""
                INSERT OR REPLACE INTO ip_info (
                    ip, hostname, country_code, region, city, loc, org,
                    is_cloud_provider, is_tor, is_vpn, is_bot, is_malicious, 
                    last_checked, username
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """, (
                ip_info["ip"], ip_info["hostname"], ip_info["country_code"],
                ip_info["region"], ip_info["city"], ip_info["loc"], ip_info["org"],
                ip_info["is_cloud_provider"], ip_info["is_tor"], ip_info["is_vpn"],
                ip_info["is_bot"], ip_info["is_malicious"], username
            ))
            db.commit()
            ip_info["username"] = username  # Agregamos el usuario al diccionario de resultados
            results.append(ip_info)


        return templates.TemplateResponse("result.html", {"request": request, "results": results})

    except Exception as e:
        logging.error(f"Error al procesar la solicitud: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")


def is_known_bot(org: str):
    """Determina si la IP pertenece a un bot conocido."""
    known_bots = ["google", "bing", "facebook", "amazonbot"]
    return any(bot in org.lower() for bot in known_bots)

def is_cloud_provider(org: str):
    """Verifica si la IP pertenece a un proveedor cloud conocido."""
    cloud_providers = ["aws", "amazon", "google", "microsoft", "azure", "gcp"]
    return any(provider in org.lower() for provider in cloud_providers)

def is_tor_ip(ip: str) -> bool:
    """Verifica si la IP pertenece a la red TOR usando un servicio público."""
    try:
        tor_check_url = "https://check.torproject.org/torbulkexitlist"
        response = requests.get(tor_check_url)

        if response.status_code == 200:
            # Verificar si la IP está en la lista de nodos de salida de TOR
            return ip in response.text.splitlines()
        return False

    except Exception as e:
        print(f"Error al verificar TOR: {e}")
        return False  # Devuelve False si hay un error


def is_vpn_ip(ip: str):
    """Aquí se puede integrar un servicio de reputación de IPs para verificar VPNs."""
    return False




        
# Inicializa la base de datos
def init_db():
    """Inicializa la base de datos y crea la tabla ip_info."""
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        # Eliminar la tabla existente ¿
        #conn.execute("DROP TABLE IF EXISTS ip_info")

        # Crear la tabla con la estructura correcta
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_info (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    country_code TEXT,
                    region TEXT,
                    city TEXT,
                    loc TEXT,
                    org TEXT,
                    is_cloud_provider INTEGER,
                    is_tor INTEGER,
                    is_vpn INTEGER,
                    is_bot INTEGER,
                    is_malicious INTEGER,
                    username TEXT,
                    last_checked TEXT,
                    is_important INTEGER DEFAULT 0
            )
        """)
        conn.commit()


if __name__ == "__main__":
    init_db()
    print("Base de datos inicializada correctamente.")
