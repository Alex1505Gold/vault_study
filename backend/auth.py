import time
from jose import jwt, JWTError
from passlib.context import CryptContext
from dotenv import dotenv_values

config = dotenv_values('.env')
SECRET_KEY = config.get('SECRET_KEY', 'dev_secret_change_me')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_SECONDS = int(config.get('ACCESS_TOKEN_EXPIRE_SECONDS', '1800'))

pwd_context = CryptContext(schemes=['argon2'], deprecated='auto')


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(username: str) -> str:
    payload = {'sub': username, 'exp': int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get('sub')
    except JWTError:
        return None
