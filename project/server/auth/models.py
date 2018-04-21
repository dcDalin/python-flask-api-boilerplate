# project/server/models.py
"""Database models for the auth endpoint"""

import datetime
import jwt

from project.server import APP, DB, BCRYPT


class User(DB.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    email = DB.Column(DB.String(255), unique=True, nullable=False)
    password = DB.Column(DB.String(255), nullable=False)
    registered_on = DB.Column(DB.DateTime, nullable=False)
    admin = DB.Column(DB.Boolean, nullable=False, default=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = BCRYPT.generate_password_hash(
            password, APP.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.admin = admin

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """

        utc_now = datetime.datetime.utcnow()
        time_delta = datetime.timedelta(days=0, seconds=5)
        payload = {
            'exp': utc_now + time_delta,
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            APP.config.get('SECRET_KEY'),
            algorithm='HS256'
        )

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, APP.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class BlacklistToken(DB.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    token = DB.Column(DB.String(500), unique=True, nullable=False)
    blacklisted_on = DB.Column(DB.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        """check whether auth token has been blacklisted"""
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False
