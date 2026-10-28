"""Emit worker-only operational logs without enabling HTTP/SDK credential debugging."""
import logging
import sys
import traceback
from pathlib import Path


def configure_logging():
    logger = logging.getLogger('worker')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(getattr(handler, '_copy_worker', False) for handler in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler._copy_worker = True
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
        logger.addHandler(handler)


def error_location(exc):
    # Keep the useful stack locations; do not log raw exception text, request bodies or locals.
    return ' > '.join(f'{Path(frame.filename).name}:{frame.lineno}:{frame.name}'
                      for frame in traceback.extract_tb(exc.__traceback__)[-5:])
