import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .logging_utils import configure_logging
from .puller import Puller
from .runner import Runner
from .store import Store


def create_app(run_worker=True):
    @asynccontextmanager
    async def lifespan(app):
        configure_logging()
        if not os.getenv('LABEL_STUDIO_TOKEN') or not os.getenv('LABEL_STUDIO_URL'):
            raise RuntimeError('LABEL_STUDIO_TOKEN and LABEL_STUDIO_URL are required')
        app.state.store = Store(os.getenv('WORKER_DATA_DIR', '/data'))
        runner = Runner(app.state.store, require_assignment=True)
        puller = Puller(app.state.store, runner)
        app.state.runner, app.state.puller = runner, puller
        logging.getLogger(__name__).info('event=worker_start worker=%s concurrency=1 heartbeat_interval=10s', app.state.store.worker_id)
        if run_worker:
            runner.start()
            puller.start()
        try:
            yield
        finally:
            if run_worker:
                runner.close()
                puller.close()
                logging.getLogger(__name__).info('event=worker_stop worker=%s', app.state.store.worker_id)

    app = FastAPI(title='Label Studio Copy Worker', version='2.0.0', lifespan=lifespan)

    @app.get('/health')
    def health():
        runner, puller = app.state.runner, app.state.puller
        alive = not run_worker or bool(runner.thread and runner.thread.is_alive() and puller.thread and puller.thread.is_alive())
        return JSONResponse(status_code=200 if alive else 503, content={
            'status': 'ok' if alive else 'unavailable', 'ready': puller.ready, 'concurrency': 1,
            'heartbeat_interval': puller.interval})

    return app


app = create_app()
