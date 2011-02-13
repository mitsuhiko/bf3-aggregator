from flaskext.script import Manager
import bf3

manager = Manager(bf3.app)


@manager.command
def initdb():
    """Create the database tables"""
    print 'Using database %s' % bf3.db.engine.url
    bf3.db.create_all()
    print 'Created tables'


@manager.command
def sync():
    """Download new messages from twitter and forums"""
    bf3.sync()
    print 'Done syncing'


if __name__ == '__main__':
    manager.run()
