import pytest
from main import create_app, connect_to_db, create_table, setup_keys

@pytest.fixture
def app():
    app = create_app()
    with app.app_context():
        create_table()  # Setup the database
        setup_keys()    # Insert test data
    yield app

@pytest.fixture
def client(app):
    return app.test_client()

def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'token' in response.get_json()

def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert 'keys' in response.get_json()
