"""Command-line entrypoint for the offensive tooling.

Usage:
    python -m red_team <attack> [--target URL]
    python -m red_team all

Every run is funneled through ``guard.assert_loopback`` first, so the tooling
physically cannot fire at anything but the local lab.
"""

from __future__ import annotations

import argparse
import sys

from .attacks import ATTACKS
from .guard import assert_loopback

DEFAULT_TARGET = "http://127.0.0.1:5000"


def _print_result(result) -> None:
    print(f"\n=== {result.name} ===")
    print(f"  Red  (/vulnerable): {result.vulnerable_outcome}")
    print(f"  Blue (/secure)    : {result.secure_outcome}")
    for note in result.notes:
        print(f"  note: {note}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="red_team",
        description="Offensive demos for the local Flask Security Lab (loopback-only).",
    )
    parser.add_argument(
        "attack",
        choices=[*ATTACKS.keys(), "all"],
        help="which attack to run, or 'all' to run the whole catalog",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"base URL of the lab (default: {DEFAULT_TARGET}); must be loopback",
    )
    args = parser.parse_args(argv)

    base = assert_loopback(args.target)
    selected = ATTACKS.keys() if args.attack == "all" else [args.attack]

    print(f"Target: {base}  (loopback verified)")
    for name in selected:
        try:
            _print_result(ATTACKS[name](base))
        except Exception as exc:  # noqa: BLE001 - keep the runner going across attacks
            print(f"\n=== {name} ===\n  error: {exc} (is the lab running?)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
