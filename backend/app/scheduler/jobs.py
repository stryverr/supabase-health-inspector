"""
APScheduler background jobs for periodic diagnostic sweeps and demo connection simulator.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.config import settings

scheduler = AsyncIOScheduler()


async def scheduled_health_sweep():
    """
    Background job triggered on an hourly interval to verify target instance health.
    """
    pass


def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(scheduled_health_sweep, "interval", minutes=60, id="hourly_sweep")
        scheduler.start()


def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
