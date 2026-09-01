"""Celery application backed by Redis (replaces APScheduler + blocking polls)."""

from __future__ import annotations

from celery import Celery

from src.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vuln_platform",
    broker=settings.broker_url,
    backend=settings.result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="scans",
    imports=("src.workers.tasks",),
    beat_schedule={
        "refresh-cisa-kev": {
            "task": "intel.refresh_kev",
            "schedule": float(settings.kev_cache_ttl_seconds),
        },
        "scheduled-estate-scan": {
            "task": "scans.scheduled",
            "schedule": float(settings.scan_schedule_hours * 3600),
        },
    },
)
