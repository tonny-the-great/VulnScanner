"""Execute authorized scans, preserve partial results, and enforce lifecycle states."""

from __future__ import annotations

import ipaddress
import logging
import os
import signal
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import ScanStateError, ScopeViolationError, VulnScannerError
from app.models.asset import Asset
from app.models.authorization import TargetType
from app.models.organization import Organization
from app.models.scan import (
    ALLOWED_SCAN_TRANSITIONS,
    TERMINAL_SCAN_STATES,
    Scan,
    ScanProfile,
    ScanStatus,
)
from app.scanning.adapters import ADAPTER_REGISTRY, RawScannerResult
from app.scanning.adapters.base import ScannerAdapter
from app.scanning.normalization import AssetNormalizer, FindingDeduplicator, normalize_raw_finding
from app.scanning.progress import emit_scan_event
from app.scanning.scope_gate import check_resolved_targets, verify_scan_scope
from app.scanning.target_validator import validate_and_normalize_target

logger = logging.getLogger(__name__)

# Seconds between cancellation polls while a scanner process runs.
CANCEL_POLL_INTERVAL = 2.0
# Limits on scanner warnings carried in events and the final message.
MAX_EVENT_WARNINGS = 10
MAX_WARNING_LENGTH = 300
MAX_WARNING_MESSAGE_LENGTH = 1000

CIDR_TARGET_TYPES = (TargetType.IPV4_CIDR, TargetType.IPV6_CIDR)


class ScanCancelledError(Exception):
    """A cancellation request won a race with a worker transition."""


def _is_ipv6_target(target_type: TargetType, value: str) -> bool:
    if target_type in (TargetType.IPV6, TargetType.IPV6_CIDR):
        return True
    if target_type == TargetType.URL:
        try:
            return ipaddress.ip_address(urlparse(value).hostname or "").version == 6
        except ValueError:
            return False
    return False


def _plan_runs(
    adapter_name: str, validated: list[tuple[TargetType, str]],
) -> tuple[list[list[str]], list[str]]:
    """Split targets into scanner invocations; return (target lists, warnings)."""
    if adapter_name == "nmap":
        # nmap scans one address family per invocation.
        ipv6 = [value for t_type, value in validated if _is_ipv6_target(t_type, value)]
        other = [value for t_type, value in validated if not _is_ipv6_target(t_type, value)]
        return [group for group in (other, ipv6) if group], []
    if adapter_name == "testssl":
        # testssl.sh takes exactly one host per invocation.
        runs: list[list[str]] = []
        warnings: list[str] = []
        for t_type, value in validated:
            if t_type in CIDR_TARGET_TYPES:
                warnings.append(f"testssl.sh cannot scan address ranges; skipped {value}")
            else:
                runs.append([value])
        return runs, warnings
    targets = [value for _, value in validated]
    return ([targets] if targets else []), []


def _result_warnings(result: RawScannerResult) -> list[str]:
    return [str(w) for w in (getattr(result, "warnings", None) or [])]


def _merge_results(
    name: str, results: list[RawScannerResult], warnings: list[str]
) -> RawScannerResult:
    """Combine the runs of one tool; plan warnings come first, each warning once."""
    if len(results) == 1:
        result = results[0]
        result.warnings = list(dict.fromkeys(list(warnings) + _result_warnings(result)))
        return result
    combined = RawScannerResult(tool_name=name, exit_code=0, execution_time_seconds=0)
    all_warnings = list(warnings)
    errors: list[str] = []
    for result in results:
        combined.assets.extend(result.assets)
        combined.findings.extend(result.findings)
        # e.g. the OS-detection notice is emitted by every nmap run of a mixed-family scan.
        all_warnings.extend(_result_warnings(result))
        combined.execution_time_seconds += result.execution_time_seconds
        if result.exit_code != 0 or result.error_message:
            combined.exit_code = result.exit_code or -1
            errors.append(result.error_message or f"{name} failed")
    combined.warnings = list(dict.fromkeys(all_warnings))
    combined.error_message = "; ".join(dict.fromkeys(errors)) or None
    return combined


def _tool_error_result(name: str, exc: Exception) -> RawScannerResult:
    if isinstance(exc, VulnScannerError):
        logger.warning("Scanner %s could not run: %s", name, exc.detail)
        message = f"Scanner {name} could not run: {exc.detail}"
    else:
        logger.error("Scanner %s failed", name, exc_info=exc)
        message = f"Scanner {name} could not execute or parse output"
    return RawScannerResult(
        tool_name=name, exit_code=-1, execution_time_seconds=0, error_message=message
    )


def _lookup_key(value: str | None) -> str:
    """Normalize an address, host or URL so scanner spellings match stored assets."""
    if not value:
        return ""
    key = value.strip()
    if "://" in key:
        try:
            key = urlparse(key).hostname or ""
        except ValueError:
            return ""
    elif key.startswith("["):
        end = key.find("]")
        if end != -1:
            key = key[1:end]
    elif key.count(":") == 1:
        host, _, port = key.partition(":")
        if port.isdigit():
            key = host
    try:
        key = str(ipaddress.ip_address(key))
    except ValueError:
        pass
    return key.lower().rstrip(".")


class ScanOrchestrator:
    def __init__(self, db: Session, scan_id: uuid.UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    def _scan(self) -> Scan:
        self.db.expire_all()
        scan = self.db.get(Scan, self.scan_id)
        if not scan:
            raise ScanStateError(f"Scan {self.scan_id} not found")
        return scan

    def transition_state(self, new_status: ScanStatus, error_message: str | None = None) -> None:
        scan = self._scan()
        current = scan.status
        if current == ScanStatus.CANCEL_REQUESTED and new_status != ScanStatus.CANCELLED:
            raise ScanCancelledError()
        if new_status not in ALLOWED_SCAN_TRANSITIONS.get(current, frozenset()):
            raise ScanStateError(
                f"Invalid scan state transition from {current.value} to {new_status.value}"
            )
        values: dict[str, Any] = {"status": new_status}
        now = datetime.now(UTC)
        # The scan starts when a worker claims it; RUNNING is a fallback.
        if new_status in (ScanStatus.VALIDATING, ScanStatus.RUNNING) and not scan.started_at:
            values["started_at"] = now
        elif new_status == ScanStatus.COMPLETED:
            values.update(completed_at=now, progress_pct=100)
        elif new_status == ScanStatus.CANCELLED:
            values["cancelled_at"] = now
        elif new_status == ScanStatus.TIMED_OUT:
            values["timed_out_at"] = now
        if error_message:
            values["error_message"] = error_message[:2000]
        result = self.db.execute(
            update(Scan).where(Scan.id == self.scan_id, Scan.status == current).values(**values)
        )
        self.db.commit()
        if result.rowcount != 1:
            if self._scan().status == ScanStatus.CANCEL_REQUESTED:
                raise ScanCancelledError()
            raise ScanStateError("Scan state changed concurrently")

    def _cancel_requested(self) -> bool:
        status = self.db.scalar(select(Scan.status).where(Scan.id == self.scan_id))
        # End the read transaction so later polls see other sessions' commits,
        # but never commit work the caller has not finished.
        if not (self.db.new or self.db.dirty or self.db.deleted):
            self.db.commit()
        return status == ScanStatus.CANCEL_REQUESTED

    def _verify_scope(self, validated: list[tuple[TargetType, str]]) -> None:
        """Re-read the authorization so a revocation or expiry stops further tools."""
        scan = self.db.get(Scan, self.scan_id)
        if scan is None:
            raise ScanStateError(f"Scan {self.scan_id} not found")
        authorization = scan.authorization
        self.db.refresh(authorization)
        # refresh() leaves lazy collections as they were; reload the target list too.
        self.db.expire(authorization, ["authorized_targets"])
        verify_scan_scope(authorization, validated)

    @staticmethod
    def _stop_process(proc: subprocess.Popen) -> None:
        """Stop the launched scanner and its subprocesses, then reap it."""
        if proc.poll() is not None:
            return
        if os.name == "nt":
            # Fixed arguments, no shell; taskkill is a Windows system tool found on PATH.
            subprocess.run(  # noqa: S603
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],  # noqa: S607
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, check=False,
            )
        else:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=5)

    def _run_tool(
        self, adapter: ScannerAdapter, validated: list[tuple[TargetType, str]], config: dict,
        file_base: str, deadline: float,
    ) -> tuple[RawScannerResult, bool, ScopeViolationError | None]:
        """Run every planned invocation of one tool; return (result, timed_out, scope error)."""
        runs, warnings = _plan_runs(adapter.name, validated)
        results: list[RawScannerResult] = []
        timed_out = False
        scope_error: ScopeViolationError | None = None
        for index, run_targets in enumerate(runs):
            if index:
                try:
                    if self._cancel_requested():
                        break
                    self._verify_scope(validated)
                except ScopeViolationError as exc:
                    scope_error = exc
                    break
                except Exception as exc:
                    # e.g. a database error: keep the earlier runs' results and
                    # skip the rest rather than losing everything collected so far.
                    self.db.rollback()
                    results.append(_tool_error_result(adapter.name, exc))
                    break
            run_base = f"{file_base}_{index}" if len(runs) > 1 else file_base
            try:
                result, timed_out = self._execute_tool(
                    adapter, run_targets, config, run_base, deadline
                )
            except Exception as exc:
                result = _tool_error_result(adapter.name, exc)
            results.append(result)
            if timed_out:
                break
        if not results:
            # Nothing runnable (or stopped before the first run): an empty, successful result.
            return (
                RawScannerResult(
                    tool_name=adapter.name,
                    exit_code=0,
                    execution_time_seconds=0,
                    warnings=list(warnings),
                ),
                timed_out,
                scope_error,
            )
        return _merge_results(adapter.name, results, warnings), timed_out, scope_error

    def _execute_tool(
        self, adapter: ScannerAdapter, targets: list[str], config: dict,
        file_base: str, deadline: float,
    ) -> tuple[RawScannerResult, bool]:
        start = time.monotonic()
        if start >= deadline:
            return RawScannerResult(tool_name=adapter.name, exit_code=-1, execution_time_seconds=0,
                                    error_message="Scan time limit exceeded"), True
        if not adapter.is_available():
            return RawScannerResult(
                tool_name=adapter.name, exit_code=-1, execution_time_seconds=0,
                error_message=f"Required scanner {adapter.name} is not installed",
            ), False
        command = adapter.build_command(targets, config, file_base)
        timed_out = False
        cancelled = False
        # Files avoid pipe deadlocks and keep scanner output on disk.
        stdout_path, stderr_path = Path(file_base + ".stdout.log"), Path(file_base + ".stderr.log")
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        with (
            stdout_path.open("w", encoding="utf-8") as stdout,
            stderr_path.open("w", encoding="utf-8") as stderr,
        ):
            # Commands come from the adapters' command builders as argument lists; no shell.
            proc = subprocess.Popen(  # noqa: S603
                command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, **kwargs
            )
            last_cancel_check = time.monotonic()
            try:
                while proc.poll() is None:
                    now = time.monotonic()
                    if now >= deadline:
                        timed_out = True
                        break
                    # Each cancellation check is a database round trip; poll it sparingly.
                    if now - last_cancel_check >= CANCEL_POLL_INTERVAL:
                        last_cancel_check = now
                        if self._cancel_requested():
                            cancelled = True
                            break
                    try:
                        proc.wait(timeout=0.25)
                    except subprocess.TimeoutExpired:
                        continue
            finally:
                self._stop_process(proc)
        result = adapter.parse_output(
            file_base, proc.returncode,
            stdout_path.read_text(encoding="utf-8", errors="replace"),
            stderr_path.read_text(encoding="utf-8", errors="replace"),
            time.monotonic() - start,
        )
        if timed_out:
            result.error_message = f"Scan time limit exceeded while executing {adapter.name}"
        elif cancelled:
            result.error_message = f"Scanner {adapter.name} cancelled"
        elif proc.returncode != 0:
            # Raw output may contain credentials; expose only a safe summary.
            result.error_message = f"Scanner {adapter.name} exited with code {proc.returncode}"
        elif result.error_message:
            result.error_message = f"Scanner {adapter.name} output could not be parsed"
        return result, timed_out

    def _persist_results(self, results: list[RawScannerResult]) -> tuple[int, int]:
        scan = self._scan()
        org_id = scan.organization_id
        # Serialize asset/finding upserts per organization (SQLite ignores the lock).
        self.db.execute(select(Organization.id).where(Organization.id == org_id).with_for_update())
        raw_assets = [a for result in results for a in result.assets]
        assets = AssetNormalizer(self.db, org_id).upsert_discovered_assets(
            raw_assets, "scan_orchestrator"
        )
        # Services added by the normalizer must be visible to asset.services (autoflush is off).
        self.db.flush()
        asset_map: dict[str, Asset] = {}
        for raw_asset, asset in zip(raw_assets, assets, strict=True):
            for value in (raw_asset.ip_address, raw_asset.hostname, raw_asset.domain,
                          asset.ip_address, asset.hostname, asset.domain):
                key = _lookup_key(value)
                if key:
                    asset_map.setdefault(key, asset)
        stored: dict[str, Asset | None] = {}

        def find_asset(address: str) -> Asset | None:
            key = _lookup_key(address)
            if not key:
                return None
            if key in asset_map:
                return asset_map[key]
            if key not in stored:
                # A finding about a host this scan did not list as an asset.
                stored[key] = self.db.scalars(
                    select(Asset).where(
                        Asset.organization_id == org_id,
                        or_(Asset.ip_address == key, func.lower(Asset.hostname) == key),
                    ).order_by(
                        # Deterministic: an exact address match first, then the most recently seen.
                        case((Asset.ip_address == key, 0), else_=1),
                        Asset.last_seen.desc(),
                        Asset.id,
                    ).limit(1)
                ).first()
            return stored[key]

        items = []
        for result in results:
            for raw in result.findings:
                asset = find_asset(raw.target_address)
                service = (
                    next(
                        (
                            s
                            for s in asset.services
                            if s.port == raw.port
                            and (not raw.protocol or s.protocol.value == raw.protocol)
                        ),
                        None,
                    )
                    if asset
                    else None
                )
                items.append(normalize_raw_finding(raw, org_id, asset, service))
        findings = FindingDeduplicator(self.db, org_id).upsert_findings(items, self.scan_id)
        self.db.flush()
        # Read ids before the commit so nothing is re-selected after it.
        finding_count = len({f.id for f in findings})
        asset_count = len({a.id for a in assets})
        scan.findings_count = finding_count
        self.db.commit()
        return finding_count, asset_count

    def _finish(self, status: ScanStatus, message: str, **payload: Any) -> None:
        if self._cancel_requested():
            status, message = ScanStatus.CANCELLED, "Scan cancelled; partial results retained"
        self.transition_state(
            status,
            error_message=message if status in (ScanStatus.FAILED, ScanStatus.TIMED_OUT) else None,
        )
        emit_scan_event(
            self.db,
            self.scan_id,
            f"scan_{status.value}",
            {"message": message, **payload},
            current_stage=status.value,
            progress_pct=100 if status == ScanStatus.COMPLETED else None,
        )

    def run_scan(self) -> None:
        scan = self._scan()
        if scan.status in TERMINAL_SCAN_STATES:
            return
        # Duplicate worker delivery must not restart an active scan.
        if scan.status not in (ScanStatus.QUEUED, ScanStatus.CANCEL_REQUESTED):
            return
        results: list[RawScannerResult] = []
        warnings: list[str] = []
        timed_out = False
        scope_error: ScopeViolationError | None = None
        claimed = False
        persisted = False
        try:
            if self._cancel_requested():
                self._finish(ScanStatus.CANCELLED, "Scan cancelled before execution")
                return
            self.transition_state(ScanStatus.VALIDATING)
            claimed = True
            settings = get_settings()
            deadline = time.monotonic() + settings.scan_timeout_seconds
            scan = self._scan()
            output_dir = Path(settings.upload_dir) / "scans" / str(scan.id)
            output_dir.mkdir(parents=True, exist_ok=True)
            scan.raw_output_path = str(output_dir)
            self.db.commit()
            emit_scan_event(
                self.db,
                self.scan_id,
                "stage_started",
                {"stage": "validating"},
                progress_pct=5,
                current_stage="validation",
            )
            if not scan.targets:
                raise ScanStateError("Scan has no targets")
            validated = [validate_and_normalize_target(t.target_value) for t in scan.targets]
            verify_scan_scope(scan.authorization, validated)
            check_resolved_targets(validated)
            for target in scan.targets:
                target.scope_verified = True
            self.db.commit()
            profile = self.db.get(ScanProfile, scan.profile_id)
            if (
                not profile
                or not profile.is_enabled
                or profile.organization_id not in (None, scan.organization_id)
            ):
                raise ScanStateError("Scan profile is unavailable")
            config = dict(profile.config_json or {})
            # Adapters choose their script/template policy from this flag;
            # the stored profile is not changed.
            run_config = {**config, "is_intrusive": bool(profile.is_intrusive)}
            tools = [
                name
                for name in ("nmap", "nuclei", "testssl")
                if config.get(name, {}).get("enabled", name == "nmap")
            ]
            if not tools:
                raise ScanStateError("Scan profile has no enabled scanners")
            # Persist the actual runtime profile before launching any tool. The
            # profile row may change later and cannot establish historical coverage.
            emit_scan_event(self.db, self.scan_id, "execution_plan", {
                "version": 1,
                "config": run_config,
                "tools": tools,
                "targets": [
                    {"type": target_type.value, "value": value} for target_type, value in validated
                ],
            })
            self.transition_state(ScanStatus.RUNNING)
            for index, name in enumerate(tools):
                if self._cancel_requested():
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                try:
                    self._verify_scope(validated)
                except ScopeViolationError as exc:
                    scope_error = exc
                    break
                emit_scan_event(
                    self.db,
                    self.scan_id,
                    "tool_started",
                    {"tool": name},
                    progress_pct=15 + index * 50 // len(tools),
                    current_stage="scanning",
                    current_tool=name,
                )
                adapter = ADAPTER_REGISTRY.get(name)
                try:
                    if adapter is None:
                        raise ScanStateError("Scanner adapter is unavailable")
                    result, tool_timed_out, tool_scope_error = self._run_tool(
                        adapter, validated, run_config, str(output_dir / f"{name}_out"), deadline,
                    )
                    timed_out = timed_out or tool_timed_out
                    scope_error = scope_error or tool_scope_error
                except Exception as exc:
                    result = _tool_error_result(name, exc)
                results.append(result)
                tool_warnings = _result_warnings(result)
                warnings.extend(tool_warnings)
                emit_scan_event(
                    self.db,
                    self.scan_id,
                    "tool_finished",
                    {
                        "tool": name,
                        "exit_code": result.exit_code,
                        "error": result.error_message,
                        "assets_found": len(result.assets),
                        "findings_found": len(result.findings),
                        "warnings": [
                            w[:MAX_WARNING_LENGTH] for w in tool_warnings[:MAX_EVENT_WARNINGS]
                        ],
                    },
                )
                if timed_out or scope_error:
                    break
            if not self._cancel_requested():
                self.transition_state(ScanStatus.PARSING)
                emit_scan_event(
                    self.db,
                    self.scan_id,
                    "stage_started",
                    {"stage": "parsing"},
                    progress_pct=75,
                    current_stage="parsing",
                )
                self.transition_state(ScanStatus.NORMALIZING)
                emit_scan_event(
                    self.db,
                    self.scan_id,
                    "stage_started",
                    {"stage": "normalizing"},
                    progress_pct=85,
                    current_stage="normalizing",
                )
            finding_count, asset_count = self._persist_results(results)
            persisted = True
            errors = [
                r.error_message or f"Scanner {r.tool_name} failed"
                for r in results
                if r.error_message or r.exit_code != 0
            ]
            if scope_error is not None:
                status, message = ScanStatus.FAILED, scope_error.detail
            elif timed_out:
                status, message = (
                    ScanStatus.TIMED_OUT,
                    "Scan time limit exceeded; partial results retained",
                )
            elif errors:
                status, message = ScanStatus.FAILED, "; ".join(errors)
            elif warnings:
                status = ScanStatus.COMPLETED
                message = ("Scan completed with warnings: " + "; ".join(dict.fromkeys(warnings)))[
                    :MAX_WARNING_MESSAGE_LENGTH
                ]
            else:
                status, message = ScanStatus.COMPLETED, "Scan completed successfully"
            self._finish(status, message, findings_count=finding_count, assets_count=asset_count)
        except ScanCancelledError:
            if not persisted:
                try:
                    self._persist_results(results)
                except Exception:
                    # Still record the cancellation so the scan does not stay in CANCEL_REQUESTED.
                    logger.exception(
                        "Could not persist partial results for cancelled scan %s", self.scan_id
                    )
                    self.db.rollback()
            self._finish(ScanStatus.CANCELLED, "Scan cancelled; partial results retained")
        except Exception as exc:
            if isinstance(exc, VulnScannerError):
                logger.warning("Scan %s failed: %s", self.scan_id, exc.detail)
            else:
                logger.exception("Scan %s failed", self.scan_id)
            self.db.rollback()
            if not claimed:
                return
            # A duplicate worker may have lost the initial state transition.
            if self._scan().status not in TERMINAL_SCAN_STATES:
                message = (
                    exc.detail
                    if isinstance(exc, VulnScannerError)
                    else "Scan execution failed; see server logs"
                )
                self._finish(ScanStatus.FAILED, message)
