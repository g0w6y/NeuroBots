"""Main entry point for the NeuroBots ML Worker."""

from __future__ import annotations

import asyncio
import signal
import sys

import typer

from config.settings import load_config, AppConfig
from events.consumer import EventConsumer
from core.pipeline import MLPipeline
from utils.logging import setup_logging, get_logger

app = typer.Typer(help="NeuroBots ML Worker - Behavioral Analytics and Anomaly Detection")


async def run_worker(config: AppConfig) -> None:
    """Main async worker loop."""
    logger = get_logger("worker")
    logger.info("Starting NeuroBots ML Worker")

    consumer = EventConsumer(config.gateway)
    pipeline = MLPipeline(config)

    await consumer.start()
    await pipeline.start()

    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    try:
        logger.info("Entering main event loop")
        while not shutdown_event.is_set():
            try:
                events = await consumer.poll_once()
                if events:
                    await pipeline.process_batch(events)
                    consumer.dedup_window_trim()
            except Exception as e:
                logger.error("Error in main loop: %s", e)
                await asyncio.sleep(1)

            await asyncio.sleep(config.gateway.poll_interval_seconds)
    except asyncio.CancelledError:
        logger.info("Worker cancelled")
    finally:
        await consumer.stop()
        await pipeline.stop()
        logger.info("ML Worker shutdown complete")


@app.command()
def start(
    redis_url: str = typer.Option("redis://127.0.0.1:6379", help="Redis URL"),
    gateway_url: str = typer.Option(
        "http://127.0.0.1:8081/admin/alerts", help="Gateway alerts endpoint"
    ),
    poll_interval: float = typer.Option(2.0, help="Polling interval in seconds"),
    log_level: str = typer.Option("INFO", help="Log level"),
) -> None:
    """Start the ML Worker."""
    import os
    os.environ["REDIS_URL"] = redis_url
    os.environ["GATEWAY_ALERTS_URL"] = gateway_url
    os.environ["POLL_INTERVAL_SECONDS"] = str(poll_interval)
    os.environ["LOG_LEVEL"] = log_level

    config = load_config()
    setup_logging(config.logging)

    asyncio.run(run_worker(config))


@app.command()
def status(
    redis_url: str = typer.Option("redis://127.0.0.1:6379", help="Redis URL"),
) -> None:
    """Check ML Worker status by reading from Redis."""
    import redis
    import orjson

    r = redis.from_url(redis_url, decode_responses=True)

    keys = r.keys("ml_risk:*")
    print(f"ML Risk Scores in Redis: {len(keys)}")
    for key in sorted(keys)[:10]:
        data = orjson.loads(r.get(key) or b"{}")
        print(f"  {key}: risk={data.get('ml_risk', 'N/A')}")

    profile_keys = r.keys("profile:*")
    print(f"\nEntity Profiles in Redis: {len(profile_keys)}")


@app.command()
def version() -> None:
    """Show ML Worker version."""
    from ml_worker import __version__
    print(f"NeuroBots ML Worker v{__version__}")


if __name__ == "__main__":
    app()
