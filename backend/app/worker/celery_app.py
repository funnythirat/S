from celery import Celery

from app.config import REDIS_URL


celery_app = Celery(
    "virus_scanner",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.worker.tasks"],
)
celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=270,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
)
