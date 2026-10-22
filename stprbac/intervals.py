"""Normalised sets of closed integer intervals over the time domain T.

An :class:`IntervalSet` is a sorted list of *disjoint* closed integer intervals
``[a, b]`` (``a <= b``). Normalisation (merging touching and overlapping
intervals) happens on construction: almost every bug in this kind of code comes
from un-normalised interval lists, so we never allow an un-normalised instance
to exist.

Two closed integer intervals *touch* when they are adjacent, e.g. ``[1, 3]`` and
``[4, 6]`` merge into ``[1, 6]`` because there is no integer strictly between 3
and 4. This matters: the model reasons over a discrete (integer) time domain.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class IntervalSet:
    """A normalised, sorted set of disjoint closed integer intervals."""

    intervals: tuple[tuple[int, int], ...] = field(default_factory=tuple)

    def __init__(self, intervals: Iterable[tuple[int, int]] = ()):
        norm = _normalise(intervals)
        object.__setattr__(self, "intervals", norm)
        # Lower endpoints, kept alongside for O(log n) bisection. Not a
        # dataclass field, so it takes no part in equality, hashing or repr.
        object.__setattr__(self, "_starts", tuple(a for a, _ in norm))

    # ---- membership ------------------------------------------------------
    def __contains__(self, t: int) -> bool:
        """Return True iff ``t`` lies in some interval. O(log n)."""
        # _starts[i] is the lower endpoint of interval i; find the last
        # interval whose start is <= t and test its upper endpoint.
        i = bisect.bisect_right(self._starts, t) - 1
        return i >= 0 and self.intervals[i][0] <= t <= self.intervals[i][1]

    # ---- set algebra -----------------------------------------------------
    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet(self.intervals + other.intervals)

    def intersect(self, other: "IntervalSet") -> "IntervalSet":
        out: list[tuple[int, int]] = []
        i = j = 0
        a, b = self.intervals, other.intervals
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            # advance the interval that ends first
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return IntervalSet(out)

    def is_empty(self) -> bool:
        return len(self.intervals) == 0

    def endpoints(self) -> list[int]:
        """All endpoints in ascending order (breakpoints for sweep-line code)."""
        pts: list[int] = []
        for a, b in self.intervals:
            pts.append(a)
            pts.append(b)
        return pts

    def first_after(self, t: int) -> int | None:
        """Smallest time ``>= t`` that is a member, or None. O(log n).

        Needed by the earliest-activation algorithm (A3): given "no access
        now", when is the next moment access becomes possible.
        """
        starts = self._starts
        i = bisect.bisect_right(starts, t) - 1
        if i >= 0 and self.intervals[i][0] <= t <= self.intervals[i][1]:
            return t  # t itself is inside an interval
        # otherwise the next interval that starts at or after t
        k = bisect.bisect_left(starts, t)
        if k < len(self.intervals):
            return self.intervals[k][0]
        return None

    # ---- misc ------------------------------------------------------------
    def __bool__(self) -> bool:
        return not self.is_empty()

    def __repr__(self) -> str:
        inner = ", ".join(f"[{a},{b}]" for a, b in self.intervals)
        return f"IntervalSet({inner})"


def _normalise(intervals: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    items = sorted((int(a), int(b)) for a, b in intervals if a <= b)
    if not items:
        return ()
    merged: list[tuple[int, int]] = [items[0]]
    for a, b in items[1:]:
        la, lb = merged[-1]
        # merge if overlapping OR touching (adjacent integers: a <= lb + 1)
        if a <= lb + 1:
            merged[-1] = (la, max(lb, b))
        else:
            merged.append((a, b))
    return tuple(merged)


# A conventional "always" interval for a bounded planning horizon.
def always(horizon: int = 10_000) -> IntervalSet:
    return IntervalSet([(0, horizon)])
