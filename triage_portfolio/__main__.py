"""CLI entry point for the incident intake demo."""
import argparse
import json
from pathlib import Path
from .core import load_samples, process_batch


def main():
    parser = argparse.ArgumentParser(description="Local rule-based IT incident triage demo")
    parser.add_argument("--input", default=str(Path(__file__).parent.parent / "data" / "sample_events.json"))
    parser.add_argument("--output", help="Optional JSON output file; defaults to stdout")
    args = parser.parse_args()
    result = process_batch(load_samples(args.input))
    rendered = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"Saved {args.output}")
    else:
        print(rendered)

if __name__ == "__main__":
    main()
