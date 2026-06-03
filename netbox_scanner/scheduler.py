from __future__ import annotations

import logging
from collections.abc import Callable

LOGGER = logging.getLogger(__name__)


def run_on_schedule(cron_expression: str, job: Callable[[], None]) -> None:
    try:
        from apscheduler.schedulers.blocking import BlockingScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError as exc:  # pragma: no cover - optional at test time
        raise RuntimeError("APScheduler is required for scheduled scans.") from exc

    scheduler = BlockingScheduler()
    scheduler.add_job(job, CronTrigger.from_crontab(cron_expression))
    LOGGER.info("Starting scheduled scans using cron=%s", cron_expression)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown(wait=False)
