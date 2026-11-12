"""Incremental OSV.dev ingestion using its public modified-ID index."""

import csv
import io
import logging
from datetime import datetime, timedelta, timezone

import httpx

from .store import Store

LOG = logging.getLogger(__name__)
API_ROOT = "https://api.osv.dev/v1/vulns"


class OSVClient:
    def __init__(self, store: Store, modified_index_url: str) -> None:
        self.store = store
        self.modified_index_url = modified_index_url

    async def sync(self) -> int:
        now = datetime.now(timezone.utc)
        cursor_text = self.store.get_meta("osv_cursor")
        if cursor_text:
            cursor = datetime.fromisoformat(cursor_text)
        else:
            # Avoid a full historical import on first launch.
            cursor = now - timedelta(hours=24)

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(self.modified_index_url)
            response.raise_for_status()
            reader = csv.reader(io.StringIO(response.text))
            candidates: list[tuple[datetime, str]] = []
            newest = cursor
            for row in reader:
                if len(row) < 2:
                    continue
                try:
                    modified = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
                except ValueError:
                    continue
                if modified < cursor:
                    # OSV documents this index as newest-first.
                    break
                location = row[1].strip()
                osv_id = location.rsplit("/", 1)[-1]
                if not osv_id:
                    continue
                candidates.append((modified, osv_id))
                newest = max(newest, modified)

            saved = 0
            failed = 0
            not_found = 0
            seen: set[str] = set()
            for modified, osv_id in candidates:
                if osv_id in seen:
                    continue
                seen.add(osv_id)
                try:
                    item = await client.get(f"{API_ROOT}/{osv_id}")
                    if item.status_code == 404:
                        not_found += 1
                        continue
                    item.raise_for_status()
                    self.store.save_vulnerability(item.json())
                    saved += 1
                except (httpx.HTTPError, ValueError) as exc:
                    failed += 1
                    LOG.warning("Unable to import OSV record %s: %s", osv_id, exc)
                    # Keep the cursor before failed records so they are retried.
                    newest = min(newest, modified)

        if newest > cursor:
            self.store.set_meta("osv_cursor", newest.isoformat())
        unique_candidates = len(seen)
        LOG.info(
            "OSV sync complete: %d unique records found in the modified index; "
            "%d fetched and saved; %d fetch failures; %d not found",
            unique_candidates, saved, failed, not_found,
        )
        return saved
