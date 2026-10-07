"""Small SQL helpers shared by search endpoints."""

from __future__ import annotations

LIKE_ESCAPE = "\\"


def like_contains(term: str) -> str:
    """`%term%` with LIKE wildcards in `term` escaped, so a search for `50%`
    or `a_b` matches those literal characters instead of acting as a pattern.
    Use together with `.ilike(pattern, escape=LIKE_ESCAPE)`."""
    escaped = term.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2).replace("%", LIKE_ESCAPE + "%").replace("_", LIKE_ESCAPE + "_")
    return f"%{escaped}%"
