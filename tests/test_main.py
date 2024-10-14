from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_homepage():
    response = client.get("/")
    print(response.text)  # Verifica qué contenido se está devolviendo

    assert response.status_code == 200
    # Ajusta el assert según el texto que realmente aparece en la respuesta HTML
    assert "Reto Meli" in response.text  # Cambia 'Hello' por el contenido que veas en el print


def test_login():
    data = {"username": "testuser", "password": "testpass"}
    response = client.post("/login", data=data)

    print(response.status_code)  # Verifica el código de estado
    print(response.text)  # Verifica el contenido de la respuesta

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "access_token" in response.json()