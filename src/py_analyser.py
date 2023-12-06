import ast
import sys
import json


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "Usage: python3 py-analyser.py <slice>.py <pattern>.json", file=sys.stderr
        )
        sys.exit(1)

    SLICE_PATH = sys.argv[1]
    PATTERN_PATH = sys.argv[2]

    SLICE_NAME = SLICE_PATH.split("/")[-1].split(".")[0]

    # Read Python slice
    try:
        with open(SLICE_PATH, "r") as f:
            slice = f.read()
    except FileNotFoundError:
        print("Slice file not found", file=sys.stderr)
        sys.exit(1)

    # Read patterns
    try:
        with open(PATTERN_PATH, "r") as f:
            patterns = json.load(f)
    except FileNotFoundError:
        print("Pattern file not found", file=sys.stderr)
        sys.exit(1)

    tree = ast.parse(slice)

    # Write results
    # print(f"Slice:\n{slice}\n")
    # print(f"Tree:\n{ast.dump(tree)}\n")
    # print(f"Patterns:\n{patterns}\n")

    OUTPUT_FILE = f"output/{SLICE_NAME}.output.json"
    with open(OUTPUT_FILE, "w") as f:
        f.write("OUTPUT")
