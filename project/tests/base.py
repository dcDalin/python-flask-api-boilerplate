# project/tests/base.py
"""Base test config"""

from flask_testing import TestCase
from project.server import APP, DB


class BaseTestCase(TestCase):
    """ Base Tests """

    def create_app(self):
        APP.config.from_object('project.server.config.TestingConfig')
        return APP

    def setUp(self):
        DB.create_all()
        DB.session.commit()

    def tearDown(self):
        DB.session.remove()
        DB.drop_all()
