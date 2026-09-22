"""M10 — firewall containment ops.

Extends the same helper rather than a second privilege path (M4's rule).
Every rule this module ever creates lives in a dedicated `SENTINELCORE`
chain, tagged `-m comment --comment "sentinelcore:<action_id>:<in|out>"` so it
can be found and removed without relying on rule numbers, which shift as
rules are added and deleted.

No rule is ever persisted: the chain is rebuilt on demand, and reconciliation
(driven by the backend, which owns the durable state in `firewall_actions`)
is what restores intent after a restart. A DROP rule that survives a reboot
with no database row behind it is exactly the failure mode TTLs exist to
prevent — so nothing here writes iptables-persistent config.
"""

from __future__ import annotations

import logging
import shlex

from helper import guards
from helper.config import config
from helper.executor import ExecutionError, run
from helper.validation import (
    ValidationError,
    validate_action_id,
    validate_direction,
    validate_protocol_port,
    validate_target,
)

logger = logging.getLogger("helper.ops.firewall")

_COMMENT_PREFIX = "sentinelcore:"


def _require_iptables() -> str:
    if config.iptables_path is None:
        raise ExecutionError("binary_missing", "iptables is not installed in the helper image")
    return config.iptables_path


def _iptables(args: list[str], *, exclusive: bool = True):
    return run([_require_iptables(), *args], timeout=config.fw_op_timeout_seconds, exclusive=exclusive)


def ensure_chain() -> None:
    """Idempotently create the SENTINELCORE chain and jump to it from INPUT
    and FORWARD. Called at helper startup and defensively before every
    mutating op, since rules are deliberately not persisted across restarts."""
    iptables = _require_iptables()

    create = run([iptables, "-N", config.fw_chain], timeout=config.fw_op_timeout_seconds, exclusive=True)
    if create.returncode != 0 and "already exists" not in create.stderr.lower():
        raise ExecutionError("chain_setup_failed", f"could not create chain: {create.stderr.strip()[:300]}")

    for parent in ("INPUT", "FORWARD"):
        check = run(
            [iptables, "-C", parent, "-j", config.fw_chain], timeout=config.fw_op_timeout_seconds, exclusive=True
        )
        if check.returncode != 0:
            insert = run(
                [iptables, "-I", parent, "1", "-j", config.fw_chain],
                timeout=config.fw_op_timeout_seconds,
                exclusive=True,
            )
            if insert.returncode != 0:
                raise ExecutionError(
                    "chain_setup_failed", f"could not jump {parent} -> {config.fw_chain}: {insert.stderr.strip()[:300]}"
                )


def _match_args(target: str, direction_flag: str, protocol: str | None, port: int | None) -> list[str]:
    args = [direction_flag, target]
    if protocol:
        args += ["-p", protocol]
    if port is not None:
        args += ["--dport", str(port)]
    return args


def _tags_for(direction: str) -> list[tuple[str, str]]:
    """(tag, iptables match flag) pairs for a direction."""
    mapping = {"inbound": [("in", "-s")], "outbound": [("out", "-d")], "both": [("in", "-s"), ("out", "-d")]}
    return mapping[direction]


def fw_check_target(params: dict) -> dict:
    """Read-only guard evaluation for the frontend's inline pre-check — never
    touches iptables, so a check can be spammed on every keystroke."""
    target_network = validate_target(params.get("target"))
    protected, reason = guards.is_protected(target_network)
    return {"target": str(target_network), "allowed": not protected, "reason": reason}


def fw_apply(params: dict) -> dict:
    action_id = validate_action_id(params.get("action_id"))
    target_network = validate_target(params.get("target"))
    protocol, port = validate_protocol_port(params.get("protocol"), params.get("port"))
    direction = validate_direction(params.get("direction"))

    # Re-checked here even though the API already checked it: assume the API
    # is compromised. This is the actual trust boundary.
    protected, reason = guards.is_protected(target_network)
    if protected:
        logger.warning("refused fw_apply action_id=%s target=%s: %s", action_id, target_network, reason)
        raise ValidationError("protected_target", reason or "target is protected")

    ensure_chain()

    applied_tags: list[str] = []
    for tag, flag in _tags_for(direction):
        comment = f"{_COMMENT_PREFIX}{action_id}:{tag}"
        match_args = _match_args(str(target_network), flag, protocol, port)
        rule_spec = [*match_args, "-m", "comment", "--comment", comment, "-j", "DROP"]

        exists = _iptables(["-C", config.fw_chain, *rule_spec])
        if exists.returncode == 0:
            applied_tags.append(tag)  # idempotent: already present
            continue

        added = _iptables(["-A", config.fw_chain, *rule_spec])
        if added.returncode != 0:
            raise ExecutionError("apply_failed", f"iptables -A failed: {added.stderr.strip()[:300]}")
        applied_tags.append(tag)

    logger.info("fw_apply action_id=%s target=%s direction=%s tags=%s", action_id, target_network, direction, applied_tags)
    return {"applied": True, "action_id": action_id, "target": str(target_network), "direction": direction, "tags": applied_tags}


def _list_raw_rules() -> list[str]:
    """`-S <chain>` lines, or [] if the chain does not exist yet."""
    result = _iptables(["-S", config.fw_chain], exclusive=False)
    if result.returncode != 0:
        return []  # chain absent (e.g. never created, or wiped externally)
    return [line for line in result.stdout.splitlines() if line.strip()]


def _parse_managed_rule(line: str) -> dict | None:
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    if "--comment" not in tokens:
        return None
    comment = tokens[tokens.index("--comment") + 1]
    if not comment.startswith(_COMMENT_PREFIX):
        return None

    parts = comment[len(_COMMENT_PREFIX) :].split(":")
    if len(parts) != 2:
        return None
    action_id, tag = parts

    target = None
    direction = None
    if "-s" in tokens:
        target = tokens[tokens.index("-s") + 1]
        direction = "inbound"
    elif "-d" in tokens:
        target = tokens[tokens.index("-d") + 1]
        direction = "outbound"

    protocol = tokens[tokens.index("-p") + 1] if "-p" in tokens else None
    port = None
    if "--dport" in tokens:
        try:
            port = int(tokens[tokens.index("--dport") + 1])
        except ValueError:
            port = None

    return {
        "action_id": action_id,
        "tag": tag,
        "direction": direction,
        "target": target,
        "protocol": protocol,
        "port": port,
        "raw": line,
    }


def fw_list(params: dict) -> dict:
    rules = [r for r in (_parse_managed_rule(line) for line in _list_raw_rules()) if r]
    return {"chain": config.fw_chain, "rules": rules}


def _delete_by_action_id(action_id: str) -> list[str]:
    removed: list[str] = []
    for line in _list_raw_rules():
        parsed = _parse_managed_rule(line)
        if parsed is None or parsed["action_id"] != action_id:
            continue
        tokens = shlex.split(line)
        tokens[0] = "-D"  # "-A CHAIN ..." -> "-D CHAIN ..."
        result = _iptables(tokens)
        if result.returncode == 0:
            removed.append(parsed["tag"])
        else:
            logger.error("failed to delete rule for action_id=%s tag=%s: %s", action_id, parsed["tag"], result.stderr.strip()[:300])
    return removed


def fw_revoke(params: dict) -> dict:
    action_id = validate_action_id(params.get("action_id"))
    # Idempotent: revoking an action_id with no matching rule still succeeds —
    # the desired end state (no such rule) is already true.
    removed = _delete_by_action_id(action_id)
    logger.info("fw_revoke action_id=%s removed_tags=%s", action_id, removed)
    return {"revoked": True, "action_id": action_id, "removed": removed}


def fw_reconcile(params: dict) -> dict:
    raw_expected = params.get("expected")
    if not isinstance(raw_expected, list):
        raise ValidationError("invalid_expected", "expected must be a list of action ids")
    expected_ids = {validate_action_id(item) for item in raw_expected}

    current = fw_list({})["rules"]
    current_ids = {r["action_id"] for r in current}

    orphans = sorted(current_ids - expected_ids)
    missing = sorted(expected_ids - current_ids)

    for action_id in orphans:
        removed = _delete_by_action_id(action_id)
        logger.warning("fw_reconcile removed orphan action_id=%s tags=%s", action_id, removed)

    return {"orphans_removed": orphans, "missing": missing, "active_count": len(expected_ids & current_ids)}
