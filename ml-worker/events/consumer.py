"""Async HTTP event consumer that polls the NeuroBots gateway for events."""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

import httpx

from config.settings import GatewayConfig
from models.schemas import GatewayEvent
from utils.logging import get_logger

logger = get_logger("event_consumer")


class EventConsumer:
    """Polls the gateway /admin/alerts endpoint and yields parsed events."""

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None
        self._seen_ids: set[str] = set()
        self._running = False

    async def start(self) -> None:
        """Initialize the HTTP client."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._config.request_timeout),
            limits=httpx.Limits(max_connections=10),
        )
        self._running = True
        logger.info(
            "EventConsumer started, polling %s every %.1fs",
            self._config.alerts_url,
            self._config.poll_interval_seconds,
        )

    async def stop(self) -> None:
        """Shut down the HTTP client."""
        self._running = False
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("EventConsumer stopped")

    async def poll_once(self) -> list[GatewayEvent]:
        """Make a single poll request and return new events."""
        if not self._client:
            raise RuntimeError("EventConsumer not started. Call start() first.")

        events: list[GatewayEvent] = []
        try:
            response = await self._client.get(self._config.alerts_url)
            response.raise_for_status()
            data = response.json()

            event_list = data if isinstance(data, list) else data.get("events", data.get("alerts", []))

            for item in event_list:
                try:
                    event = GatewayEvent(**item)
                    event_key = f"{event.subject}:{event.timestamp.isoformat()}:{event.path}"
                    if event_key not in self._seen_ids:
                        self._seen_ids.add(event_key)
                        events.append(event)
                except Exception as e:
                    logger.warning("Failed to parse event: %s - %s", e, item)
                    continue

            if events:
                logger.info("Fetched %d new events", len(events))

        except httpx.ConnectError:
            logger.debug("Gateway not available at %s", self._config.alerts_url)
        except httpx.TimeoutException:
            logger.warning("Timeout polling gateway at %s", self._config.alerts_url)
        except httpx.HTTPStatusError as e:
            logger.warning("HTTP error %d from gateway", e.response.status_code)
        except Exception as e:
            logger.error("Unexpected error polling gateway: %s", e)

        return events

    async def stream(self) -> AsyncIterator[list[GatewayEvent]]:
        """Continuously yield batches of events."""
        while self._running:
            events = await self.poll_once()
            yield events
            await asyncio.sleep(self._config.poll_interval_seconds)

    def dedup_window_trim(self, max_size: int = 10000) -> None:
        """Trim the dedup window to prevent memory growth."""
        if len(self._seen_ids) > max_size:
            keep = list(self._seen_ids)[-max_size // 2 :]
            self._seen_ids = set(keep)
