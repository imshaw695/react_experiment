import traceback
import logging
from website.models import Log
from website import db

class Sql_alchemy_log_handler(logging.Handler):

    def emit(self, record):
        trace = None
        exc = record.__dict__['exc_info']
        if exc:
            trace = traceback.format_exc(chain=exc)
        log = Log(
            logger=record.__dict__['name'],
            level=record.__dict__['levelname'],
            trace=trace,
            msg=record.__dict__['msg'],)
        db.session.add(log)
        db.session.commit()