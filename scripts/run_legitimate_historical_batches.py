
from pathlib import Path
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent.parent

COLLECTOR = BASE / "scripts/collect_legitimate_historical_batch.py"
OUTPUT_DIR = BASE / "data/legitimate/historical_batches"

START_BATCH = 2
END_BATCH = 20

# Short pause between successful batches.
PAUSE_SECONDS = 3


def main():
    print("=" * 65, flush=True)
    print("TYPOSQUATSHIELD - LEGITIMATE HISTORICAL BATCH RUNNER", flush=True)
    print("=" * 65, flush=True)

    completed = 0
    skipped = 0

    for number in range(START_BATCH, END_BATCH + 1):
        batch_id = f"batch_{number:03d}"
        output = OUTPUT_DIR / f"{batch_id}_historical.csv"

        if output.exists():
            print(f"[SKIP] {batch_id}: already exported", flush=True)
            skipped += 1
            continue

        print(f"\nProcessing {batch_id}", flush=True)

        command = [
            sys.executable,
            str(COLLECTOR),
            "--batch",
            str(number),
            "--execute",
        ]

        result = subprocess.run(
            command,
            cwd=BASE,
            check=False,
        )

        if result.returncode != 0:
            print(f"[STOP] {batch_id} failed.", flush=True)
            print("Previous exports remain unchanged.", flush=True)
            sys.exit(1)

        if not output.exists():
            print(
                f"[STOP] {batch_id} did not create an export.",
                flush=True,
            )
            sys.exit(1)

        completed += 1
        time.sleep(PAUSE_SECONDS)

    print("\n" + "=" * 65, flush=True)
    print("LEGITIMATE HISTORICAL COLLECTION FINISHED", flush=True)
    print("=" * 65, flush=True)
    print("New batches completed:", completed, flush=True)
    print("Existing batches skipped:", skipped, flush=True)
    print("[SUCCESS] Batch runner completed.", flush=True)


if __name__ == "__main__":
    main()
