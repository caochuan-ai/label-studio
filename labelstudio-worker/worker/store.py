import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / 'jobs.sqlite3'
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, owner INTEGER NOT NULL, project INTEGER NOT NULL,
                    request TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
                    phase TEXT NOT NULL DEFAULT 'queued', total INTEGER NOT NULL DEFAULT 0,
                    current_task INTEGER, file_progress REAL NOT NULL DEFAULT 0,
                    target_project INTEGER, planned INTEGER NOT NULL DEFAULT 0,
                    error TEXT, created REAL NOT NULL, updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS items (
                    job TEXT NOT NULL REFERENCES jobs(id), source INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', target INTEGER, error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(job, source)
                );
                CREATE INDEX IF NOT EXISTS items_status ON items(job,status,source);
                CREATE INDEX IF NOT EXISTS jobs_history ON jobs(owner,project,created);
            ''')
            db.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('worker_id',?)", (str(uuid4()),))
            self.worker_id = db.execute("SELECT value FROM metadata WHERE key='worker_id'").fetchone()[0]
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, job_id, owner, request):
        with self.connect() as db:
            now = time.time()
            db.execute('INSERT OR IGNORE INTO jobs(id,owner,project,request,created,updated) VALUES(?,?,?,?,?,?)',
                       (job_id, owner, request['project_id'], json.dumps(request), now, now))
            old = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            old_request = json.loads(old['request'])
            new_request = dict(request)
            for data in (old_request, new_request):
                data.pop('label_studio_token', None)
                data.pop('attempt', None)
            if old['owner'] != owner or old_request != new_request:
                raise ValueError('Idempotency key already used with different configuration')
        return self.get(job_id, owner)

    def update(self, job_id, **values):
        allowed = {'status', 'phase', 'total', 'current_task', 'file_progress', 'target_project', 'planned', 'error'}
        if not set(values) <= allowed:
            raise ValueError('Invalid job update')
        values['updated'] = time.time()
        with self.connect() as db:
            db.execute('UPDATE jobs SET ' + ','.join(k + '=?' for k in values) + ' WHERE id=?',
                       (*values.values(), job_id))

    def get(self, job_id, owner=None, private=False):
        with self.connect() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            if not row or (owner is not None and row['owner'] != owner):
                return None
            job = dict(row)
            counts = dict(db.execute('SELECT status,count(*) FROM items WHERE job=? GROUP BY status', (job_id,)))
            job['completed'] = counts.get('completed', 0)
            job['failed'] = counts.get('failed', 0)
            job['progress'] = (100 * (job['completed'] + job['failed']) / job['total']) if job['total'] else 0
            if job['status'] == 'completed':
                job['progress'] = 100
            job['errors'] = [dict(r) for r in db.execute(
                "SELECT source,error FROM items WHERE job=? AND status='failed' ORDER BY source LIMIT 100", (job_id,))]
            request = json.loads(job.pop('request'))
            job['attempt'] = request.get('attempt', 1)
            job['new_project_name'] = request['new_project_name']
            job['crop'] = request['crop']
            job['source_storage'] = {k: request['source_storage'][k] for k in ('bucket', 'prefix', 'region_name')}
            if private:
                job['request'] = request
            return job

    def history(self, owner, project, offset=0):
        with self.connect() as db:
            ids = [r[0] for r in db.execute('SELECT id FROM jobs WHERE owner=? AND project=? ORDER BY created DESC LIMIT 50 OFFSET ?',
                                            (owner, project, offset))]
        return [self.get(job_id, owner) for job_id in ids]

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE jobs SET status='queued',phase='recovering' WHERE status='running'")

    def next_job(self):
        with self.connect() as db:
            row = db.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
        return self.get(row[0], private=True) if row else None

    def add_items(self, job_id, ids):
        with self.connect() as db:
            db.executemany('INSERT OR IGNORE INTO items(job,source) VALUES(?,?)', [(job_id, n) for n in ids])
            count = db.execute('SELECT count(*) FROM items WHERE job=?', (job_id,)).fetchone()[0]
        self.update(job_id, total=count)

    def next_item(self, job_id):
        with self.connect() as db:
            row = db.execute("SELECT source FROM items WHERE job=? AND status='pending' ORDER BY source LIMIT 1", (job_id,)).fetchone()
        return row[0] if row else None

    def finish_item(self, job_id, source, target=None, error=None):
        with self.connect() as db:
            db.execute('UPDATE items SET status=?,target=?,error=? WHERE job=? AND source=?',
                       ('failed' if error else 'completed', target, error, job_id, source))

    def begin_item(self, job_id, source):
        with self.connect() as db:
            db.execute('UPDATE items SET attempts=attempts+1 WHERE job=? AND source=?', (job_id, source))
            attempts = db.execute('SELECT attempts FROM items WHERE job=? AND source=?', (job_id, source)).fetchone()[0]
        if attempts > 3:
            raise ValueError('This task interrupted the worker three times; check resource limits before retrying')

    def retry(self, job_id, owner):
        with self.connect() as db:
            changed = db.execute("UPDATE jobs SET status='queued',phase='queued',error=NULL WHERE id=? AND owner=? AND status IN ('failed','partial')", (job_id, owner)).rowcount
            if changed:
                db.execute("UPDATE items SET status='pending',error=NULL,attempts=0 WHERE job=? AND status='failed'", (job_id,))
        return bool(changed)

    def accept_assignment(self, assignment):
        from .schemas import CopyRequest
        request = CopyRequest(**assignment['request']).model_dump(mode='json')
        request['attempt'] = assignment['attempt']
        job_id = assignment['id']
        if request['idempotency_key'] != job_id:
            raise ValueError('Assignment does not match request ID')
        self.create(job_id, assignment['owner'], request)
        with self.connect() as db:
            old = json.loads(db.execute('SELECT request FROM jobs WHERE id=?', (job_id,)).fetchone()[0])
            previous = old.get('attempt', 1)
            if assignment['attempt'] < previous:
                raise ValueError('Stale copy attempt')
            if assignment['attempt'] > previous:
                db.execute("UPDATE jobs SET status='queued',phase='queued',error=NULL WHERE id=?", (job_id,))
                db.execute("UPDATE items SET status='pending',error=NULL,attempts=0 WHERE job=? AND status='failed'", (job_id,))
            # Never persist the Label Studio token; it only comes from the worker environment.
            db.execute('UPDATE jobs SET request=? WHERE id=?', (json.dumps(request), job_id))
        return self.get(job_id, private=True)
