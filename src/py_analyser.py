import ast
import sys
import json

from domain.Policy import Policy
from domain.Pattern import Pattern
from domain.Vulnerabilities import Vulnerabilities

from visitors.NodeProcessor import NodeProcessor


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "Usage: python3 py-analyser.py <slice>.py <pattern>.json", file=sys.stderr
        )
        sys.exit(1)

    SLICE_PATH = sys.argv[1]
    PATTERN_PATH = sys.argv[2]

    SLICE_NAME = SLICE_PATH.split("/")[-1].split(".")[0]

    # Read Python slice and generate ast
    tree = None
    try:
        with open(SLICE_PATH, "r") as f:
            slice = f.read()
            tree = ast.parse(slice)
    except FileNotFoundError:
        print("Slice file not found", file=sys.stderr)
        sys.exit(1)

    # Read patterns and create policy
    policy = None
    try:
        with open(PATTERN_PATH, "r") as f:
            patterns_json = json.load(f)
            patterns = set()
            for pattern in patterns_json:
                patterns.add(Pattern.from_json(pattern))
            policy = Policy(patterns)
    except FileNotFoundError:
        print("Pattern file not found", file=sys.stderr)
        sys.exit(1)

    # Find illegal flows
    vulnerabilities = Vulnerabilities(policy)
    nodeProcessor = NodeProcessor(vulnerabilities)
    nodeProcessor.visit(tree)

    illegal_flows = [flow.to_json() for flow in vulnerabilities.get_illegal_flows()]

    OUTPUT_FILE = f"output/{SLICE_NAME}.output.json"
    with open(OUTPUT_FILE, "w") as f:
        f.write(json.dumps(illegal_flows, indent=4) + "\n")
