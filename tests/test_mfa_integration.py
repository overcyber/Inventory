import bcrypt
import pyotp
from models import User, db

def test_full_mfa_login_flow(app):
    password='Mfa-Test-Password-9842'
    secret=pyotp.random_base32()
    with app.app_context():
        old=User.query.filter_by(username='mfa_test').first()
        if old:
            db.session.delete(old); db.session.commit()
        user=User(username='mfa_test',
                  password_hash=bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode(),
                  role='user',mfa_enabled=True,mfa_secret=secret,
                  must_change_password=False)
        db.session.add(user); db.session.commit()
    client=app.test_client()
    client.get('/login')
    with client.session_transaction() as sess:
        csrf=sess['_csrf_token']
    response=client.post('/login',
        data={'username':'mfa_test','password':password,'_csrf_token':csrf},
        follow_redirects=False)
    assert response.status_code in (302,303)
    assert '/verify_mfa' in response.headers['Location']
    client.get('/verify_mfa')
    with client.session_transaction() as sess:
        csrf=sess['_csrf_token']
        assert sess.get('mfa_username')=='mfa_test'
    code=pyotp.TOTP(secret).now()
    response=client.post('/verify_mfa',
        data={'code':code,'_csrf_token':csrf},follow_redirects=False)
    assert response.status_code in (302,303)
    with client.session_transaction() as sess:
        assert sess.get('username')=='mfa_test'
        assert 'mfa_username' not in sess
