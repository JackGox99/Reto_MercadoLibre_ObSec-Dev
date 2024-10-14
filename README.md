# Reto MercadoLibre - ObSec Dev

## Descripción
Este proyecto consiste en una API desarrollada en **Python** utilizando **FastAPI**. La API permite realizar consultas de IPs, gestionar IPs importantes y tiene autenticación mediante **JWT**. Además, se han añadido contenedores con **Docker** para facilitar su despliegue.

---

## Estructura del Proyecto

### Reto Meli
```
Reto Meli
├── auth.py                 # Módulo para autenticación y generación de tokens JWT
├── database.py             # Módulo para gestión de la base de datos SQLite
├── main.py                 # Archivo principal de la API
├── Dockerfile              # Definición del contenedor Docker
├── docker-compose.yml      # Orquestación de servicios Docker
├── templates               # Plantillas HTML para las vistas
│   ├── base.html
│   ├── dashboard.html
│   ├── filter.html
│   ├── important_ips.html
│   ├── login.html
│   └── register.html
├── static                  # Archivos estáticos (CSS, imágenes)
│   ├── image.png
│   └── styles.css
├── tests                   # Tests unitarios para asegurar calidad
│   ├── test_auth.py
│   ├── test_database.py
│   └── test_main.py
├── requirements.txt        # Lista de dependencias
├── database.db             # Archivo de la base de datos SQLite
└── secret_key.txt          # Archivo con clave secreta para JWT
```

---
## Instalación y Ejecución Local
1. Clona el Repositorio:

   ```bash
   git clone https://github.com/tu-usuario/Reto_MercadoLibre_ObSec-Dev.git
   cd Reto_MercadoLibre_ObSec-Dev

   # Para subir el contenedor
   docker-compose up -d

   # Para bajar el contenedor
   docker-compose down

---

## **3. Documentación sobre la aplicación, su funcionamiento y consideraciones**

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