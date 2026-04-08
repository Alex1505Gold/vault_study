import os
import uuid
import hashlib
import pyotp
from dotenv import dotenv_values
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

from auth import hash_password, verify_password, create_token, decode_token
from store import (
    init_db,
    UPLOAD_DIR,
    get_user,
    create_user_local,
    create_or_update_user_sso,
    set_user_vault,
    add_file_record,
    list_files_for_user,
    get_file_record,
    delete_file_record,
    log_event,
    get_audit_for_user,
    sha256_file,
)

config = dotenv_values('.env')
FRONTEND_URL = config.get('FRONTEND_URL', 'http://127.0.0.1:5500')
SESSION_SECRET = config.get('SESSION_SECRET', 'CHANGE_ME_SESSION_SECRET')
GOOGLE_CLIENT_ID = config.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = config.get('GOOGLE_CLIENT_SECRET', '')
COOKIE_NAME = 'access_token'
MAX_FILE_SIZE_BYTES = int(config.get('MAX_FILE_SIZE_BYTES', str(20 * 1024 * 1024)))

app = FastAPI(title='Zero-Knowledge Vault Backend')
init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
    expose_headers=['X-Orig-Filename'],
)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )


def set_auth_cookie(resp: JSONResponse | RedirectResponse, token: str):
    resp.set_cookie(key=COOKIE_NAME, value=token, httponly=True, samesite='lax', secure=False, path='/')


def clear_auth_cookie(resp: JSONResponse | RedirectResponse):
    resp.delete_cookie(COOKIE_NAME, path='/')


def current_user_from_cookie(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    username = decode_token(token)
    if not username:
        return None
    return get_user(username)


@app.get('/')
async def root():
    return {'ok': True, 'service': 'zk-vault-backend'}


@app.post('/api/register')
async def api_register(payload: dict):
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    if not username or not password:
        raise HTTPException(400, 'Заполни username и password')
    if len(username) < 3:
        raise HTTPException(400, 'Username слишком короткий (>= 3)')
    if len(password) < 8:
        raise HTTPException(400, 'Пароль слишком короткий (>= 8)')
    if get_user(username):
        log_event(username, 'register', 'fail', 'username already exists')
        raise HTTPException(409, 'Пользователь уже существует')

    secret = pyotp.random_base32()
    create_user_local(username=username, password_hash=hash_password(password), totp_secret=secret)
    uri = pyotp.TOTP(secret).provisioning_uri(username, issuer_name='ZeroKnowledgeVault')
    log_event(username, 'register', 'success', 'local user created')
    return {'ok': True, 'totp_secret': secret, 'otpauth_uri': uri}


@app.post('/api/login')
async def api_login(payload: dict):
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    user = get_user(username)
    if not user:
        log_event(username or None, 'login', 'fail', 'user not found')
        raise HTTPException(401, 'Пользователь не найден')
    if user.get('password') is None:
        log_event(username, 'login', 'fail', 'sso account')
        raise HTTPException(400, 'Этот аккаунт создан через SSO. Войди через SSO.')
    if not verify_password(password, user['password']):
        log_event(username, 'login', 'fail', 'wrong password')
        raise HTTPException(401, 'Неверный пароль')
    if user.get('totp'):
        log_event(username, 'login_password', 'success', 'password accepted, waiting for totp')
        return {'ok': True, 'next': 'totp'}

    token = create_token(username)
    resp = JSONResponse({'ok': True, 'next': 'done'})
    set_auth_cookie(resp, token)
    log_event(username, 'login', 'success', 'logged in without totp')
    return resp


@app.post('/api/totp')
async def api_totp(payload: dict):
    username = (payload.get('username') or '').strip()
    code = (payload.get('code') or '').strip()
    user = get_user(username)
    if not user:
        log_event(username or None, 'totp', 'fail', 'user not found')
        raise HTTPException(401, 'Пользователь не найден')
    if not user.get('totp'):
        log_event(username, 'totp', 'fail', 'totp not enabled')
        raise HTTPException(400, 'У пользователя не включен TOTP')
    totp = pyotp.TOTP(user['totp'])
    if not totp.verify(code, valid_window=1):
        log_event(username, 'totp', 'fail', 'wrong otp code')
        raise HTTPException(401, 'Неверный OTP-код')

    token = create_token(username)
    resp = JSONResponse({'ok': True})
    set_auth_cookie(resp, token)
    log_event(username, 'login', 'success', 'logged in with totp')
    return resp


@app.get('/api/me')
async def api_me(request: Request):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    return {
        'username': user['username'],
        'email': user.get('email'),
        'sso_provider': user.get('sso_provider'),
        'vault_configured': bool(user.get('vault_verifier')),
    }


@app.post('/api/logout')
async def api_logout(request: Request):
    user = current_user_from_cookie(request)
    resp = JSONResponse({'ok': True})
    clear_auth_cookie(resp)
    log_event(user['username'] if user else None, 'logout', 'success', 'session closed')
    return resp


@app.get('/api/vault/info')
async def api_vault_info(request: Request):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    return {
        'configured': bool(user.get('vault_verifier')),
        'salt': user.get('vault_salt'),
    }


@app.post('/api/vault/setup')
async def api_vault_setup(request: Request, payload: dict):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    salt = (payload.get('salt') or '').strip()
    verifier = (payload.get('verifier') or '').strip()
    if not salt or not verifier:
        raise HTTPException(400, 'Не переданы salt/verifier')
    if user.get('vault_verifier'):
        raise HTTPException(409, 'Vault уже настроен')
    set_user_vault(user['username'], salt, verifier)
    log_event(user['username'], 'vault_setup', 'success', 'vault password configured')
    return {'ok': True}


@app.post('/api/vault/verify')
async def api_vault_verify(request: Request, payload: dict):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    verifier = (payload.get('verifier') or '').strip()
    if not user.get('vault_verifier'):
        raise HTTPException(400, 'Vault еще не настроен')
    if verifier != user['vault_verifier']:
        log_event(user['username'], 'vault_unlock', 'fail', 'wrong vault password')
        raise HTTPException(401, 'Неверный пароль хранилища')
    log_event(user['username'], 'vault_unlock', 'success', 'vault unlocked on client')
    return {'ok': True}


@app.get('/api/files')
async def api_files(request: Request):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    items = list_files_for_user(user['username'])
    return {'items': items}


@app.post('/api/files/upload')
async def api_files_upload(
    request: Request,
    file: UploadFile = File(...),
    original_filename: str = Form(...),
    plaintext_sha256: str = Form(...),
):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')

    data = await file.read()
    if not data:
        raise HTTPException(400, 'Файл пустой')
    if len(data) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(413, 'Файл слишком большой')

    stored_name = f'{uuid.uuid4().hex}.bin'
    path = os.path.join(UPLOAD_DIR, stored_name)
    with open(path, 'wb') as f:
        f.write(data)

    container_sha256 = hashlib.sha256(data).hexdigest()
    record = add_file_record(
        username=user['username'],
        orig_filename=original_filename,
        stored_name=stored_name,
        container_sha256=container_sha256,
        plaintext_sha256=plaintext_sha256,
        size_bytes=len(data),
    )
    log_event(user['username'], 'file_upload', 'success', f'uploaded {original_filename}')
    return {'ok': True, 'item': record}


@app.get('/api/files/{file_id}/download')
async def api_files_download(request: Request, file_id: int):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    row = get_file_record(file_id)
    if not row or row['username'] != user['username']:
        raise HTTPException(404, 'Файл не найден')
    path = os.path.join(UPLOAD_DIR, row['stored_name'])
    if not os.path.exists(path):
        log_event(user['username'], 'file_download', 'fail', f'missing file id={file_id}')
        raise HTTPException(404, 'Контейнер файла отсутствует')
    resp = FileResponse(path, media_type='application/octet-stream', filename=row['stored_name'])
    resp.headers['X-Orig-Filename'] = row['orig_filename']
    log_event(user['username'], 'file_download', 'success', f'downloaded {row["orig_filename"]}')
    return resp


@app.post('/api/files/{file_id}/check-integrity')
async def api_check_integrity(request: Request, file_id: int):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    row = get_file_record(file_id)
    if not row or row['username'] != user['username']:
        raise HTTPException(404, 'Файл не найден')
    path = os.path.join(UPLOAD_DIR, row['stored_name'])
    if not os.path.exists(path):
        log_event(user['username'], 'integrity_check', 'fail', f'missing file id={file_id}')
        raise HTTPException(404, 'Контейнер файла отсутствует')
    current = sha256_file(path)
    ok = current == row['container_sha256']
    log_event(user['username'], 'integrity_check', 'success' if ok else 'fail', f'{row["orig_filename"]}: {"ok" if ok else "mismatch"}')
    return {'ok': ok, 'expected': row['container_sha256'], 'actual': current}


@app.delete('/api/files/{file_id}')
async def api_delete_file(request: Request, file_id: int):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    row = get_file_record(file_id)
    if not row or row['username'] != user['username']:
        raise HTTPException(404, 'Файл не найден')
    deleted = delete_file_record(file_id)
    log_event(user['username'], 'file_delete', 'success', f'deleted {deleted["orig_filename"]}')
    return {'ok': True}


@app.get('/api/audit')
async def api_audit(request: Request):
    user = current_user_from_cookie(request)
    if not user:
        raise HTTPException(401, 'Не авторизован')
    return {'items': get_audit_for_user(user['username'])}


@app.get('/api/sso/google')
async def sso_google(request: Request):
    if 'google' not in oauth._clients:
        raise HTTPException(500, 'Google SSO не настроен (нет GOOGLE_CLIENT_ID/SECRET)')
    redirect_uri = request.url_for('sso_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get('/api/sso/google/callback')
async def sso_google_callback(request: Request):
    if 'google' not in oauth._clients:
        raise HTTPException(500, 'Google SSO не настроен')
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get('userinfo')
    if not userinfo:
        userinfo = await oauth.google.parse_id_token(request, token)
    email = userinfo.get('email')
    if not email:
        raise HTTPException(400, 'SSO не вернул email')
    username_hint = (userinfo.get('given_name') or userinfo.get('name') or 'user').lower().replace(' ', '')
    user = create_or_update_user_sso(provider='google', email=email, username_hint=username_hint)
    jwt_token = create_token(user['username'])
    resp = RedirectResponse(url=f'{FRONTEND_URL}/#dashboard', status_code=302)
    set_auth_cookie(resp, jwt_token)
    log_event(user['username'], 'login_sso', 'success', 'google login')
    return resp
