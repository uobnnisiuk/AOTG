"""Module entry point for the dry-run CLI."""

import argparse
import json
import sys
from pathlib import Path

from .adapters import adapter_for
from .artifacts import publish_artifact, read_artifact
from .core import MAX_TRIALS, SEED_DEFAULT, plan_experiment, run_experiment
from .judge import compare_run
from .kit import build_kit, verify_kit
from .manifest import load_manifest, validate_manifest


def _inspect(args):
    if args.manifest is not None:
        return load_manifest(args.manifest)
    manifest = adapter_for(args.adapter).detect()
    validate_manifest(manifest)
    return manifest


def _plan(args):
    return plan_experiment(load_manifest(args.manifest), seed=args.seed)


def _bench(args):
    resume = read_artifact(args.resume) if args.resume is not None else None
    return run_experiment(
        read_artifact(args.plan), resume=resume, trial_budget=args.trial_budget
    )


def _compare(args):
    return compare_run(read_artifact(args.run))


def _build(args):
    return build_kit(read_artifact(args.run), read_artifact(args.decision))


def _verify(args):
    return verify_kit(read_artifact(args.kit), read_artifact(args.run))


def _parser():
    parser = argparse.ArgumentParser(
        description="Inspect hardware and exercise the AOTG mock pipeline"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser(
        "inspect", help="Inspect a manifest or run a local read-only probe"
    )
    source = inspect.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest", type=Path)
    source.add_argument("--adapter", choices=("linux", "windows"))
    inspect.set_defaults(handler=_inspect)

    plan = commands.add_parser("plan", help="Generate a bounded mock plan")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--seed", type=int, default=SEED_DEFAULT)
    plan.set_defaults(handler=_plan)

    bench = commands.add_parser("bench", help="Execute the synthetic schedule")
    bench.add_argument("--plan", type=Path, required=True)
    bench.add_argument("--resume", type=Path, help="Read a previous mock run artifact")
    bench.add_argument(
        "--trial-budget",
        type=int,
        default=MAX_TRIALS,
        help="Set the maximum number of new trials in this invocation",
    )
    bench.set_defaults(handler=_bench)

    compare = commands.add_parser(
        "compare", help="Apply quality and resource gates to the mock run"
    )
    compare.add_argument("--run", type=Path, required=True)
    compare.set_defaults(handler=_compare)

    build = commands.add_parser(
        "build-kit", help="Generate the selected mock kit as metadata"
    )
    build.add_argument("--run", type=Path, required=True)
    build.add_argument("--decision", type=Path, required=True)
    build.set_defaults(handler=_build)

    verify = commands.add_parser(
        "verify-kit", help="Verify mock kit integrity using the run"
    )
    verify.add_argument("--kit", type=Path, required=True)
    verify.add_argument("--run", type=Path, required=True)
    verify.set_defaults(handler=_verify)

    for command in (inspect, plan, bench, compare, build, verify):
        command.add_argument(
            "--output", type=Path, help="Write to a new file instead of stdout"
        )
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        document = args.handler(args)
        if args.output is None:
            print(
                json.dumps(
                    document,
                    allow_nan=False,
                    ensure_ascii=True,
                    sort_keys=True,
                    indent=2,
                )
            )
        else:
            publish_artifact(args.output, document)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"aotg: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
