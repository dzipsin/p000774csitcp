"""
storage.py - JSON persistence for IncidentReports.

Responsibilities:
  - Create and manage the reports/ directory
  - Serialise IncidentReport dataclasses to JSON
  - Write atomically (temp file + rename) to avoid partial writes
  - Handle disk/permission errors gracefully
  - Provide basic read-back for debugging and future persistence features

Design notes:
  - We use atomic write (write to `.tmp` then rename) so readers never see
    a half-written file. Rename is atomic on POSIX; Windows os.replace() is
    also atomic.
  - Filename strategy: `inc_<first-5-of-uuid>.json`. Short enough to ls cleanly,
    unique enough (UUID4 collision on 5 hex chars is negligible for a demo).
  - Nested dataclasses serialise via dataclasses.asdict() — no custom encoder
    needed as long as all nested types are dataclass, dict, list, or primitive.
"""

from __future__ import annotations

import json
import logging
import math
import os
import tempfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, List, Optional

from models import IncidentReport

log = logging.getLogger(__name__)


class ReportStorage:
    """File-based storage for IncidentReports.

    Thread-safe for concurrent writes of different incidents. Concurrent writes
    to the same incident rely on last-write-wins semantics (tmp+rename).
    """

    def __init__(self, reports_dir: str = "reports"):
        """
        Args:
            reports_dir: directory path (relative or absolute) where
                         inc_<id>.json files are written.
        """
        self._dir = Path(reports_dir).expanduser().resolve()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create the reports directory if it doesn't exist."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            log.debug("Reports directory ready: %s", self._dir)
        except OSError as e:
            log.error("Could not create reports directory %s: %s", self._dir, e)
            raise

    @property
    def directory(self) -> Path:
        return self._dir

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, report: IncidentReport) -> Optional[Path]:
        """Write an IncidentReport to disk atomically.

        Returns the path on success, None on failure. Errors are logged
        but not raised so the pipeline can continue even if storage fails.
        """
        try:
            path = self._path_for_incident(report.incident_summary.incident_id)
            payload = _report_to_dict(report)

            # Atomic write: write to a temp file in the same dir, then rename.
            # tempfile in same dir ensures the rename is on the same filesystem
            # (rename across filesystems is not atomic).
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix=path.name + ".",
                suffix=".tmp",
                dir=str(self._dir),
            )

            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    json.dump(
                        payload,
                        f,
                        indent=2,
                        ensure_ascii=False,
                        default=_json_fallback,
                    )
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except (OSError, AttributeError):
                        # fsync not available everywhere (e.g. some Windows setups)
                        # Not critical; the rename still provides the atomicity we need.
                        pass

                # os.replace() is atomic on both POSIX and Windows
                os.replace(tmp_path, path)
                log.info(
                    "Report saved: %s (incident=%s, version=%s)",
                    path.name,
                    report.incident_summary.incident_id[:8],
                    report.incident_summary.report_version,
                )
                return path

            except Exception:
                # Clean up temp file if the write or rename failed
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

        except Exception as e:
            log.error(
                "Failed to save report for incident %s: %s",
                report.incident_summary.incident_id, e,
            )
            return None

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def load_raw(self, incident_id: str) -> Optional[dict]:
        """Load a report by incident ID. Returns the raw dict, or None if missing/invalid.

        Intended for debugging and future persistence features. We don't
        deserialise back into dataclasses because we'd need to reconstruct
        the whole nested class tree; the dict form is sufficient for
        inspection and API responses.
        """
        try:
            path = self._path_for_incident(incident_id)
            if not path.exists():
                return None
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("Failed to load report for incident %s: %s", incident_id, e)
            return None

    def list_reports(self) -> List[dict]:
        """Return all saved reports as raw dicts, sorted by generated_at desc.

        Lenient: ignores files that don't parse rather than failing the whole call.
        """
        reports: List[dict] = []

        try:
            for path in sorted(self._dir.glob("inc_*.json")):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        reports.append(json.load(f))
                except (OSError, json.JSONDecodeError) as e:
                    log.warning("Skipping unreadable report %s: %s", path.name, e)
        except OSError as e:
            log.error("Failed to list reports directory: %s", e)
            return []

        # Sort by generated_at descending (most recent first).
        # Missing or malformed timestamps sink to the bottom.
        reports.sort(
            key=lambda r: r.get("incident_summary", {}).get("generated_at", ""),
            reverse=True,
        )
        return reports

    def clear_all(self) -> int:
        """Delete every report file. Returns count of deleted files.

        Used by the dashboard "Clear" button.
        """
        count = 0
        try:
            for path in self._dir.glob("inc_*.json"):
                try:
                    path.unlink()
                    count += 1
                except OSError as e:
                    log.warning("Could not delete %s: %s", path.name, e)
        except OSError as e:
            log.error("Failed to iterate reports directory for clear: %s", e)
        log.info("Cleared %d report file(s)", count)
        return count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _path_for_incident(self, incident_id: str) -> Path:
        """Derive the on-disk path for a given incident ID."""
        # Use first 8 chars of UUID — UUID4 collision probability is negligible
        # for any realistic incident volume and it keeps filenames readable.
        safe_id = incident_id.replace("/", "").replace("\\", "")[:8]
        return self._dir / f"inc_{safe_id}.json"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _report_to_dict(report: IncidentReport) -> dict:
    """Convert an IncidentReport (and all nested dataclasses) to a plain dict.

    dataclasses.asdict() recurses into dataclass fields, including nested
    dataclasses, lists of dataclasses, and dicts. Tuples become lists.
    """
    return asdict(report)


def _json_fallback(obj: Any) -> Any:
    """Fallback encoder for values asdict() couldn't handle.

    Also sanitises float NaN/Infinity which are invalid JSON.
    """
    # NaN/Infinity are not valid JSON
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj

    # Catch any dataclass instance that slipped through (shouldn't happen
    # but defensive). is_dataclass accepts both classes and instances; we
    # only want instances here.
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)  # type: ignore[arg-type]

    # Path objects, UUID, etc
    if hasattr(obj, "__str__"):
        return str(obj)

    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")