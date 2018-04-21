# project/server/config.py
"""App configurations dev/production/testing"""

import os
BASEDIR = os.path.abspath(os.path.dirname(__file__))
POSTGRES_LOCAL_BASE = 'postgresql://postgres:password@localhost/'
DATABASE_NAME = 'python_flask_api_boilerplate'


class BaseConfig:  # pylint: disable=too-few-public-methods
    """Base configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(BaseConfig):  # pylint: disable=too-few-public-methods
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = POSTGRES_LOCAL_BASE + DATABASE_NAME


class TestingConfig(BaseConfig):  # pylint: disable=too-few-public-methods
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = POSTGRES_LOCAL_BASE + DATABASE_NAME + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False


class ProductionConfig(BaseConfig):  # pylint: disable=too-few-public-methods
    """Production configuration."""
    SECRET_KEY = 'my_precious'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgresql:///example'
