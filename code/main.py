
import argparse
import csv
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

sys.path.insert(0, str(BASE_DIR))

from intent import is_deletion
from identity import IdentityResolver
from evidence import Evidence
from planner import plan


def resolve_path(path):
    """Resolve relative paths from the project root."""
    path = Path(path)

    if path.is_absolute():
        return path

    return PROJECT_ROOT / path


def run(ds, req, out, ocr=False):
    dataset_dir = resolve_path(ds)
    request_file = resolve_path(req)
    output_file = resolve_path(out)

    # Check required input files before processing.
    required_files = [
        dataset_dir / "user_identities.csv",
        dataset_dir / "user_audit_log.csv",
        dataset_dir / "evidence_files.csv",
        request_file,
    ]

    for path in required_files:
        if not path.is_file():
            raise FileNotFoundError(
                f"Required file not found: {path}"
            )

    print("Dataset folder:", dataset_dir)
    print("Request file:", request_file)
    print("Output file:", output_file)

    idr = IdentityResolver(str(dataset_dir))
    ev = Evidence(str(dataset_dir), ocr)
    rows = []

    with request_file.open(
        "r", encoding="utf-8-sig", newline=""
    ) as f:
        reader = csv.DictReader(f)

        required_columns = {
            "case_id", "email", "audit_at", "request_text"
        }
        missing = required_columns - set(reader.fieldnames or [])

        if missing:
            raise ValueError(
                f"Request CSV is missing columns: {sorted(missing)}"
            )

        for r in reader:
            case_id = r["case_id"]
            request_text = r["request_text"] or ""

            print(f"\n{'=' * 45}")
            print("CASE:", case_id)
            print("Email:", r["email"])
            print("Audit cutoff:", r["audit_at"])

            # Check whether this request asks for deletion.
            if not is_deletion(request_text):
                print("Decision: NOT_APPLICABLE")
                rows.append((case_id, "NOT_APPLICABLE", []))
                continue

            # Resolve identifiers for this user.
            ids = idr.resolve(r["email"])

            print("Direct identity count:", len(ids.direct))
            print("Direct identities:", ids.direct)
            print("Weak identities:", ids.weak)

            # Test the supplied email against the resolved identifiers.
            print(
                "Email matches direct identities:",
                ids.direct_in(r["email"])
            )

            # Find evidence no later than the audit cutoff.
            try:
                file_id, resources = ev.find(
                    ids, 
                    r["audit_at"],
                    r.get("submitted_at")
                )
            except Exception as exc:
                print("Evidence search error:", repr(exc))
                rows.append((case_id, "INCOMPLETE", []))
                continue

            print("Evidence file:", file_id)
            print("Matched resources:", list(resources.keys())[:20])

            if not resources:
                print(
                    "Decision: INCOMPLETE — no matching evidence found"
                )
                rows.append((case_id, "INCOMPLETE", []))
                continue

            # Use the existing planner for matched evidence.
            try:
                status, steps = plan(resources, file_id)
            except Exception as exc:
                print("Planner error:", repr(exc))
                rows.append((case_id, "INCOMPLETE", []))
                continue

            # Avoid emitting a COMPLETE result with no proof steps.
            if status == "COMPLETE" and not steps:
                print(
                    "WARNING: Planner returned COMPLETE without steps."
                )
                status = "INCOMPLETE"

            print("Decision:", status)
            print("Number of steps:", len(steps))
            rows.append((case_id, status, steps))

    # Sort deterministically by case ID.
    rows.sort(key=lambda row: row[0])

    # Write output.csv in the required format.
    output_file.parent.mkdir(
        parents=True, exist_ok=True
    )

    with output_file.open(
        "w", encoding="utf-8", newline=""
    ) as f:
        writer = csv.writer(f)
        writer.writerow([
            "case_id",
            "deletion_status",
            "steps_json"
        ])

        for case_id, status, steps in rows:
            writer.writerow([
                case_id,
                status,
                json.dumps(
                    steps,
                    separators=(",", ":"),
                    ensure_ascii=False
                )
            ])

    print(f"\nWrote {len(rows)} rows -> {output_file}")

    # Create the required usage report.
    report_dir = BASE_DIR / "evaluation"
    report_dir.mkdir(parents=True, exist_ok=True)

    report = (
        "# Usage Report\n\n"
        "- Model provider: Not called directly by main.py\n"
        "- Requests processed: " + str(len(rows)) + "\n"
        "- OCR enabled: " + str(ocr) + "\n\n"
        "Review intent.py, identity.py, evidence.py, and planner.py "
        "to record any model calls or external API usage accurately.\n"
    )

    (report_dir / "usage_report.md").write_text(
        report, encoding="utf-8"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Deletion audit agent"
    )

    parser.add_argument(
        "--dataset", default="dataset"
    )
    parser.add_argument(
        "--requests", default="dataset/deletion_requests.csv"
    )
    parser.add_argument(
        "--out", default="output.csv"
    )
    parser.add_argument(
        "--ocr", action="store_true"
    )

    args = parser.parse_args()

    run(
        args.dataset,
        args.requests,
        args.out,
        args.ocr
    )
