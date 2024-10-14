from auth import create_access_token, verify_token

def test_verify_token():
    token = create_access_token({"sub": "testuser"})
    payload = verify_token(token)

    # Verifica el tipo de valor devuelto
    print(payload)

    # Asegúrate de que el payload sea un diccionario
    assert isinstance(payload, dict), "El token decodificado no es un diccionario"
    assert payload.get("sub") == "testuser"
