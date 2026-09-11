"""Task dispatcher adapters implementing :class:`TaskDispatcherPort`."""

from __future__ import annotations


class CeleryTaskDispatcher:
    """Enqueues scan work onto the Celery worker pool."""

    def dispatch_scan(
        self,
        job_id: str,
        targets: list[str],
        scanners: list[str],
        profile: str = "home",
        requested_by: str | None = None,
    ) -> str:
        from src.workers.tasks import run_scan_task

        async_result = run_scan_task.delay(
            job_id, targets, scanners, profile, requested_by
        )
        return str(async_result.id)
