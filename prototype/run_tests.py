import subprocess
import time
import datetime
import json
import os

TESTS = [
    "T1059.001",  # Example: Add your desired technique IDs here
    "T1086",
    # ... more techniques
]

LOG_FILE = "nids_test_log.json"  # Store results in a JSON file

def run_test(technique_id):
    os.environ["ATOMIC_RED_TEAM_TEST"] = technique_id # Set environment variable

    try:
        start_time = datetime.datetime.now().isoformat()
        result = subprocess.run(
            ["invoke", "atomic", "test", technique_id], capture_output=True, text=True, check=True
        )
        end_time = datetime.datetime.now().isoformat()
        return {
            "technique_id": technique_id,
            "start_time": start_time,
            "end_time": end_time,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.CalledProcessError as e:
        end_time = datetime.datetime.now().isoformat()
        return {
            "technique_id": technique_id,
            "start_time": start_time,
            "end_time": end_time,
            "stdout": e.stdout,
            "stderr": e.stderr,
            "returncode": e.returncode,
            "error": str(e),
        }
    finally:
        del os.environ["ATOMIC_RED_TEAM_TEST"] # Remove environment variable


def main():
    all_results = []
    for technique_id in TESTS:
        print(f"Running test for {technique_id}...")
        result = run_test(technique_id)
        all_results.append(result)
        time.sleep(60)  # Optional: Add a delay between tests

    with open(LOG_FILE, "w") as f:
        json.dump(all_results, f, indent=4)


if __name__ == "__main__":
    main()
