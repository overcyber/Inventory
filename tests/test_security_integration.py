def test_api_returns_json_401_without_session(app):
    client=app.test_client()
    response=client.get('/api/v1/assets')
    assert response.status_code==401
    assert response.is_json

def test_csrf_rejects_session_mutation_without_token(app):
    client=app.test_client()
    client.get('/login')
    with client.session_transaction() as sess:
        sess['username']='admin'; sess['role']='admin'
    response=client.post('/api/v1/tokens',json={'name':'csrf-reject','scopes':['ingest']})
    assert response.status_code==400
    assert response.get_json()['reason']=='csrf_token_invalid'

def test_csrf_accepts_valid_token_for_admin_session(app):
    client=app.test_client()
    client.get('/login')
    with client.session_transaction() as sess:
        sess['username']='admin'; sess['role']='admin'; token=sess['_csrf_token']
    response=client.post('/api/v1/tokens',json={'name':'csrf-ok','scopes':['ingest']},
                         headers={'X-CSRF-Token':token})
    assert response.status_code==201
    assert response.get_json()['token'].startswith('inv_')
