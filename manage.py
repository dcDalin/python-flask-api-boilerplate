# manage.py
"""This module performs database initialization and running the app"""


from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from project.server import APP, DB

MIGRATE = Migrate(APP, DB)
MANAGER = Manager(APP)

# migrations
MANAGER.add_command('db', MigrateCommand)


@MANAGER.command
def create_db():
    """Creates the DB tables."""
    DB.create_all()


@MANAGER.command
def drop_db():
    """Drops the DB tables."""
    DB.drop_all()


if __name__ == '__main__':
    MANAGER.run()
