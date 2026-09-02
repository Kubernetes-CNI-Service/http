#!/usr/bin/env python3
"""User-facing entry point for single and directory-batch analysis."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT))

from lib.snapshot import default_report_path, is_supported_archive
from scripts.validate_ib_topology import main as validate_main


REPORT_SUFFIX = "-topology-validation.xlsx"


def is_snapshot_directory(path: Path) -> bool:
    return path.is_dir() and (path / "ibdiagnet2.net_dump").is_file()


def is_iblinkinfo_file(path: Path) -> bool:
    return (
        path.is_file()
        and "iblinkinfo" in path.name.casefold()
        and path.suffix.casefold() in {".log", ".txt", ".out"}
    )


def ib_info_directories(output_directory: Path) -> list[Path]:
    """Return supported ib-info locations associated with an output directory."""
    candidates = [
        output_directory / "ib-info",
        output_directory / "infiniband" / "ib-info",
        output_directory.parent / "99-output-monitor" / "infiniband" / "ib-info",
    ]
    default_output = (PROJECT / "99-output-p2p").resolve()
    if output_directory.resolve() == default_output:
        candidates.insert(0, PROJECT.parent / "ib-info")
    result: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_dir() and resolved not in seen:
            seen.add(resolved)
            result.append(resolved)
    return result


def link_ib_info_inputs(output_directory: Path) -> list[Path]:
    """Link discovered ibdiagnet/iblinkinfo inputs into the output directory."""
    linked: list[Path] = []
    sources: list[Path] = []
    for ib_info in ib_info_directories(output_directory):
        sources.extend(
            path for path in ib_info.rglob("*")
            if path.is_file()
            and not path.name.startswith("._")
            and (
                ("ibdiagnet" in path.name.casefold() and is_supported_archive(path))
                or is_iblinkinfo_file(path)
            )
        )

    by_name: dict[str, Path] = {}
    for source in sorted(set(path.resolve() for path in sources)):
        previous = by_name.get(source.name)
        if previous is not None and previous != source:
            raise ValueError(
                f"multiple ib-info inputs have the same filename {source.name!r}: "
                f"{previous} and {source}"
            )
        by_name[source.name] = source

    for name, source in by_name.items():
        destination = output_directory / name
        relative_target = Path(os.path.relpath(source, start=output_directory))
        if destination.is_symlink():
            try:
                current = destination.resolve(strict=True)
            except OSError as exc:
                raise ValueError(f"broken ib-info link in output directory: {destination}") from exc
            if current != source:
                raise ValueError(
                    f"ib-info link points to a different file: {destination} -> {current}; "
                    f"expected {source}"
                )
            if destination.readlink().is_absolute():
                temporary = destination.with_name(f".{destination.name}.relative-link.tmp")
                if temporary.exists() or temporary.is_symlink():
                    raise ValueError(f"temporary link path already exists: {temporary}")
                temporary.symlink_to(relative_target)
                os.replace(temporary, destination)
                print(f"[RELINKED] {destination} -> {relative_target}")
        elif destination.exists():
            if destination.resolve() != source:
                raise ValueError(
                    f"cannot create ib-info link because path already exists: {destination}"
                )
        else:
            destination.symlink_to(relative_target)
            print(f"[LINKED] {destination} -> {relative_target}")
        linked.append(destination)
    return linked


def classify_inputs(paths: list[str]) -> tuple[Path, Path]:
    """Return ``(snapshot, workbook)`` regardless of positional order."""
    if len(paths) != 2:
        raise ValueError("exactly two inputs are required: one archive and one CVT .xlsx")
    resolved = [Path(value).expanduser().resolve() for value in paths]
    archives = [
        path for path in resolved
        if is_supported_archive(path) or is_snapshot_directory(path) or is_iblinkinfo_file(path)
    ]
    workbooks = [path for path in resolved if path.suffix.casefold() == ".xlsx"]
    if len(archives) != 1 or len(workbooks) != 1 or archives[0] == workbooks[0]:
        raise ValueError(
            "inputs must contain exactly one ibdiagnet snapshot or iblinkinfo log, "
            "and one CVT .xlsx workbook"
        )
    for path in (archives[0], workbooks[0]):
        if not path.exists():
            raise ValueError(f"input file not found: {path}")
    return archives[0], workbooks[0]


def preferred_cvt_names(directory: Path) -> list[str]:
    """Return CVT names in discovery order, preferring the real P2P source name."""
    names: list[str] = []
    for candidate in (
        directory.parent / "p2p.xlsx",
        directory / "p2p.xlsx",
    ):
        if not candidate.is_file():
            continue
        try:
            name = f"{candidate.resolve(strict=True).stem}-cvt.xlsx".casefold()
        except OSError:
            continue
        if name not in names:
            names.append(name)
    for fallback in ("cvt.xlsx", "p2p-cvt.xlsx"):
        if fallback not in names:
            names.append(fallback)
    return names


def discover_batch_inputs(directory: Path) -> tuple[Path, list[Path]]:
    """Find one CVT workbook and all supported actual-topology inputs."""
    directory = directory.expanduser().resolve()
    if not directory.is_dir():
        raise ValueError(f"batch input directory not found: {directory}")

    linked_inputs = link_ib_info_inputs(directory)
    if linked_inputs:
        print(f"ib-info inputs linked into batch directory: {len(linked_inputs)}")

    workbooks = sorted(
        path for path in directory.iterdir()
        if path.is_file()
        and path.suffix.casefold() == ".xlsx"
        and not path.name.casefold().endswith(REPORT_SUFFIX)
        and "cvt" in path.stem.casefold()
    )
    preferred = [
        path for preferred_name in preferred_cvt_names(directory)
        for path in workbooks if path.name.casefold() == preferred_name
    ]
    if preferred:
        workbook = preferred[0]
    elif len(workbooks) == 1:
        workbook = workbooks[0]
    elif not workbooks:
        raise ValueError(
            f"no CVT workbook found in {directory}; expected cvt.xlsx or a name "
            "containing 'cvt'. Generate it with p2p-to-validation.py before analysis"
        )
    else:
        names = ", ".join(path.name for path in workbooks)
        raise ValueError(f"multiple CVT workbooks found in {directory}: {names}")

    snapshots = sorted(
        (
            path for path in directory.iterdir()
            if (
                (
                    "ibdiagnet" in path.name.casefold()
                    and (
                        (path.is_file() and is_supported_archive(path))
                        or is_snapshot_directory(path)
                    )
                )
                or is_iblinkinfo_file(path)
            )
        ),
        key=lambda path: path.name.casefold(),
    )
    if not snapshots:
        raise ValueError(
            f"no ibdiagnet snapshots or iblinkinfo logs found in {directory}; "
            "supported archives are .tgz/.tar.gz/.tar/.zip, plus snapshot directories "
            "containing ibdiagnet2.net_dump and iblinkinfo*.log/.txt/.out"
        )
    return workbook, snapshots


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze an ibdiagnet snapshot or iblinkinfo log against a CVT workbook, "
            "or batch-analyze all supported inputs in a directory. With no arguments, "
            "use output-p2p/99-output-p2p in or below the current directory, "
            "or the setup-managed 99-output-p2p link beside this script."
        )
    )
    parser.add_argument(
        "inputs", nargs="*", metavar="INPUT",
        help=(
            "one directory for batch mode, or one actual-topology input and one "
            "CVT .xlsx in either order"
        ),
    )
    parser.add_argument("-i", "--ibdiagnet", metavar="ARCHIVE")
    parser.add_argument("--iblinkinfo", metavar="LOG")
    parser.add_argument("-p", "--p2p", metavar="CVT_XLSX")
    parser.add_argument("-o", "--output", metavar="FILE")
    parser.add_argument("--port-profiles", metavar="CSV")
    args = parser.parse_args(argv)
    args.batch_dir = None
    positional_mode = bool(args.inputs)
    option_mode = bool(args.ibdiagnet or args.iblinkinfo or args.p2p)
    if not positional_mode and not option_mode:
        current = Path.cwd()
        candidates = []
        if current.name.casefold() in {"output-p2p", "99-output-p2p"}:
            candidates.append(current)
        candidates.extend((
            current / "99-output-p2p",
            current / "output-p2p",
            PROJECT / "99-output-p2p",
            PROJECT / "output-p2p",
        ))
        batch_directory = next(
            (candidate for candidate in candidates if candidate.is_dir()), None
        )
        if batch_directory is None:
            parser.error(
                "no arguments supplied and no output directory was found; run DAY0 "
                "setup to create tools/ibdiagnet-analyze-tool/99-output-p2p, or "
                "provide a 99-output-p2p directory explicitly"
            )
        args.batch_dir = str(batch_directory.resolve())
        args.ibdiagnet = None
        args.iblinkinfo = None
        args.p2p = None
        return args
    if positional_mode and option_mode:
        parser.error("do not mix positional inputs with --ibdiagnet/--p2p")
    if positional_mode:
        batch_candidate = Path(args.inputs[0]).expanduser() if len(args.inputs) == 1 else None
        if batch_candidate is not None and batch_candidate.is_dir():
            args.batch_dir = str(batch_candidate.resolve())
            args.ibdiagnet = None
            args.iblinkinfo = None
            args.p2p = None
        else:
            try:
                actual, workbook = classify_inputs(args.inputs)
                args.iblinkinfo = str(actual) if is_iblinkinfo_file(actual) else None
                args.ibdiagnet = None if args.iblinkinfo else str(actual)
                args.p2p = str(workbook)
            except ValueError as exc:
                parser.error(str(exc))
    elif not (bool(args.ibdiagnet) ^ bool(args.iblinkinfo)) or not args.p2p:
        parser.error(
            "provide one batch directory, two positional inputs, or exactly one of "
            "--ibdiagnet/--iblinkinfo together with --p2p"
        )
    return args


def forwarded_args(snapshot: Path, workbook: Path, output: Path | None,
                   port_profiles: str | None,
                   iblinkinfo: bool | None = None) -> list[str]:
    if iblinkinfo is None:
        iblinkinfo = is_iblinkinfo_file(snapshot)
    actual_option = "--iblinkinfo" if iblinkinfo else "--ibdiagnet"
    forwarded = [actual_option, str(snapshot), "--p2p", str(workbook)]
    if output is not None:
        forwarded.extend(["--output", str(output)])
    if port_profiles:
        forwarded.extend(["--port-profiles", port_profiles])
    return forwarded


def run_batch(args: argparse.Namespace) -> None:
    try:
        workbook, snapshots = discover_batch_inputs(Path(args.batch_dir))
    except ValueError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc

    output_dir = Path(args.output).expanduser().resolve() if args.output else None
    if output_dir is not None and output_dir.suffix.casefold() == ".xlsx":
        raise SystemExit("ERROR: --output must be a directory in batch mode")

    print(f"Batch directory: {args.batch_dir}")
    print(f"CVT workbook:    {workbook}")
    print(f"Snapshots:       {len(snapshots)}")
    successes: list[Path] = []
    skipped: list[Path] = []
    failures: list[tuple[Path, str]] = []
    reserved_outputs: set[Path] = set()
    for index, snapshot in enumerate(snapshots, 1):
        default_output = default_report_path(snapshot)
        output = (output_dir / default_output.name) if output_dir else default_output
        if output in reserved_outputs:
            failures.append((snapshot, f"output name collision: {output.name}"))
            continue
        reserved_outputs.add(output)
        if output.is_file():
            newest_input = max(workbook.stat().st_mtime_ns, snapshot.stat().st_mtime_ns)
            if newest_input <= output.stat().st_mtime_ns:
                skipped.append(output)
                print(f"\n[{index}/{len(snapshots)}] Skipping: {snapshot.name}")
                print(f"[SKIPPED] Result exists and is current: {output}")
                continue
            print(f"\n[{index}/{len(snapshots)}] Reanalyzing: {snapshot.name}")
            stale_inputs = []
            if workbook.stat().st_mtime_ns > output.stat().st_mtime_ns:
                stale_inputs.append("CVT workbook")
            if snapshot.stat().st_mtime_ns > output.stat().st_mtime_ns:
                stale_inputs.append("actual-topology input")
            print(
                f"[STALE] Newer input(s): {', '.join(stale_inputs)}; "
                f"result will be replaced: {output}"
            )
        else:
            print(f"\n[{index}/{len(snapshots)}] Analyzing: {snapshot.name}")
        try:
            validate_main(forwarded_args(snapshot, workbook, output, args.port_profiles))
        except SystemExit as exc:
            if exc.code not in (None, 0):
                failures.append((snapshot, str(exc.code)))
                print(f"[FAILED] {snapshot.name}: {exc.code}", file=sys.stderr)
                continue
        successes.append(output)
        print(f"[OK] {snapshot.name} -> {output}")

    print("\nBatch summary:")
    print(f"  Successful: {len(successes)}")
    for output in successes:
        print(f"    {output}")
    print(f"  Skipped:    {len(skipped)}")
    for output in skipped:
        print(f"    {output} (already exists)")
    print(f"  Failed:     {len(failures)}")
    for snapshot, reason in failures:
        print(f"    {snapshot}: {reason}")
    if failures:
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.batch_dir:
        run_batch(args)
        return
    validate_main(forwarded_args(
        Path(args.iblinkinfo or args.ibdiagnet), Path(args.p2p),
        Path(args.output) if args.output else None, args.port_profiles,
        iblinkinfo=bool(args.iblinkinfo),
    ))


if __name__ == "__main__":
    main()
