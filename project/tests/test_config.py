# project/tests/test_config.py
"""Test app configurations"""

import unittest

from flask import current_app
from flask_testing import TestCase

from project.server import APP

POSTGRES_LOCAL_BASE = 'postgresql://postgres:password@localhost/'
DATABASE_NAME = 'python_flask_api_boilerplate'


class TestDevelopmentConfig(TestCase):
    """Testing App Development configuration"""

    def create_app(self):
        """Get dev mode"""
        APP.config.from_object('project.server.config.DevelopmentConfig')
        return APP

    def test_app_is_development(self):
        """Dev assertions method"""
        self.assertFalse(APP.config['SECRET_KEY'] is 'my_precious')
        self.assertTrue(APP.config['DEBUG'] is True)
        self.assertFalse(current_app is None)
        self.assertTrue(
            APP.config['SQLALCHEMY_DATABASE_URI'] ==
            POSTGRES_LOCAL_BASE + DATABASE_NAME
        )


class TestTestingConfig(TestCase):
    """Testing App Test Configuration"""

    def create_app(self):
        """Get app test config"""
        APP.config.from_object('project.server.config.TestingConfig')
        return APP

    def test_app_is_testing(self):
        """Testing method assertions"""
        self.assertFalse(APP.config['SECRET_KEY'] is 'my_precious')
        self.assertTrue(APP.config['DEBUG'])
        self.assertTrue(
            APP.config['SQLALCHEMY_DATABASE_URI'] ==
            POSTGRES_LOCAL_BASE + DATABASE_NAME + '_test'
        )


class TestProductionConfig(TestCase):
    """Testing App Production Config"""

    def create_app(self):
        """Get the production config"""
        APP.config.from_object('project.server.config.ProductionConfig')
        return APP

    def test_app_is_production(self):
        """Assert App Debug mode is false"""
        self.assertTrue(APP.config['DEBUG'] is False)


if __name__ == '__main__':
    unittest.main()
