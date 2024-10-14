# Reto MercadoLibre - ObSec Dev

## Descripción
Este proyecto consiste en una API desarrollada en **Python** utilizando **FastAPI**. La API permite realizar consultas de IPs, gestionar IPs importantes y tiene autenticación mediante **JWT**. Además, se han añadido contenedores con **Docker** para facilitar su despliegue.

---

## Estructura del Proyecto

Reto Meli/ │ ├── auth.py # Módulo para autenticación y generación de tokens JWT ├── database.py # Módulo para gestión de base de datos SQLite ├── main.py # Archivo principal de la API ├── Dockerfile # Definición del contenedor Docker ├── docker-compose.yml# Orquestación de servicios Docker ├── templates/ # Plantillas HTML para las vistas ├── static/ # Archivos estáticos (CSS, imágenes) └── tests/ # Tests unitarios para asegurar calidad


---

## Instalación y Ejecución Local
1. **Clona el Repositorio:**
   ```bash
   git clone https://github.com/tu-usuario/Reto_MercadoLibre_ObSec-Dev.git
   cd Reto_MercadoLibre_ObSec-Dev


Crea un entorno virtual y activa:

bash
Copiar código
python -m venv env
source env/bin/activate  # En Linux/macOS
env\Scripts\activate      # En Windows
Instala dependencias:

bash
Copiar código
pip install -r requirements.txt
Ejecuta la aplicación:

bash
Copiar código
uvicorn main:app --reload

Uso con Docker
Construir la imagen:

bash
Copiar código
docker build -t reto-api .
Ejecutar la aplicación con Docker:

bash
Copiar código
docker run -d -p 8000:8000 reto-api
Con Docker Compose:

bash
Copiar código
docker-compose up --build

Endpoints Principales
/ip-info: Consulta información de una IP.
/add-important-ip: Marca una IP como importante.
/important-ips: Muestra las IPs importantes.
Autenticación con JWT
Para acceder a endpoints protegidos, es necesario incluir un token JWT en las solicitudes. El token se genera tras iniciar sesión y se envía en la cabecera como:

makefile
Copiar código
Authorization: Bearer <token>
Ejecución de Tests
bash
Copiar código
pytest tests/


---

## **3. Documentación sobre la aplicación, su funcionamiento y consideraciones**

Voy a generar un archivo **`DOCUMENTACION.md`** que detalla el funcionamiento de la aplicación y cualquier consideración técnica.

### **DOCUMENTACION.md**
```markdown
# Documentación del Proyecto - Reto MercadoLibre ObSec Dev

## Descripción General
Este proyecto es una API desarrollada con **Python** y **FastAPI**. La aplicación permite gestionar IPs, autenticación con JWT, y está preparada para su despliegue en Docker.

## Funcionalidades Principales
1. **Autenticación y Autorización:**
   - Los usuarios deben autenticarse utilizando JWT para acceder a recursos protegidos.
   
2. **Gestión de IPs:**
   - Consulta información de IPs y gestión de IPs importantes.
   - Información almacenada en **SQLite**.

3. **Pruebas Unitarias:**
   - Asegurar la correcta funcionalidad mediante tests con `pytest`.

---

## Requisitos del Sistema
- Python 3.11+
- Docker (Opcional, para despliegue)
- Acceso a Internet para API externas.

---

## Estructura del Código
- **`main.py`**: Define los endpoints de la API y la lógica principal.
- **`auth.py`**: Contiene la lógica de autenticación y generación de tokens JWT.
- **`database.py`**: Gestiona la conexión y consultas a la base de datos SQLite.

---

## Despliegue con Docker
Puedes usar Docker para simplificar la ejecución:
```bash
docker build -t reto-api .
docker run -d -p 8000:8000 reto-api