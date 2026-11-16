"""Describe the measurement machine, for the metadata of benchmark results.

Standard library only. The CPU model and memory size are read from Linux
``/proc``; on other systems those fields fall back to ``platform`` or ``None``.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def _cpuinfo() -> dict[str, str]:
    """First processor block of /proc/cpuinfo, or {} if unavailable."""
    try:
        text = Path("/proc/cpuinfo").read_text()
    except OSError:
        return {}
    out: dict[str, str] = {}
    for line in text.split("\n\n", 1)[0].splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


def _physical_cores() -> int | None:
    """Distinct (physical id, core id) pairs in /proc/cpuinfo."""
    try:
        blocks = Path("/proc/cpuinfo").read_text().strip().split("\n\n")
    except OSError:
        return None
    cores = set()
    for block in blocks:
        fields = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
        fields = {k.strip(): v.strip() for k, v in fields.items()}
        if "core id" in fields:
            cores.add((fields.get("physical id", "0"), fields["core id"]))
    return len(cores) or None


def _max_mhz() -> float | None:
    try:
        khz = Path("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").read_text()
        return int(khz) / 1000
    except (OSError, ValueError):
        return None


def _mem_total_gib() -> float | None:
    """Usable memory (MemTotal), in GiB. Installed RAM is usually slightly more."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 2**20, 1)
    except (OSError, ValueError, IndexError):
        pass
    return None


def _opa_version() -> str | None:
    opa = shutil.which("opa")
    if not opa:
        return None
    try:
        out = subprocess.run([opa, "version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def describe() -> dict:
    """Hardware and software of the current machine, as JSON-ready values."""
    cpu = _cpuinfo()
    return {
        "os": platform.platform(),
        "arch": platform.machine(),
        "cpu_model": cpu.get("model name") or platform.processor() or None,
        "physical_cores": _physical_cores(),
        "logical_cpus": os.cpu_count(),
        "cpu_max_mhz": _max_mhz(),
        "mem_total_gib": _mem_total_gib(),
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "opa": _opa_version(),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(describe(), indent=2))
