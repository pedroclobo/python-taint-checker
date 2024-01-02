import ast
from copy import deepcopy
import sys
import json
import os
import itertools

from domain.Policy import Policy
from domain.Pattern import Pattern
from domain.Vulnerabilities import Vulnerabilities

from visitors.ControlFlowNodeCounter import ControlFlowNodeCounter
from visitors.NodeProcessor import NodeProcessor
from visitors.ControlFlowTransformer import ControlFlowTransformer
from visitors.UninitializedVariableDetector import UninitializedVariableDetector


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

    control_flow_node_counter = ControlFlowNodeCounter()
    control_flow_node_counter.visit(tree)

    branches = list(itertools.product(
        [(False, 1)] + [(True, i + 1) for i in range(3)],
        repeat=control_flow_node_counter.get_count(),
    ))
    trees = []

    # Remove if statements from tree
    for branch in branches:
        control_flow_transformer = ControlFlowTransformer(branch)
        tree_copy = deepcopy(tree)
        control_flow_transformer.visit(tree_copy)
        trees.append(tree_copy)

    illegal_flows = set()
    vulnerabilities = Vulnerabilities(policy)

    trees = [tree] if len(trees) == 0 else trees

    for i, tree in enumerate(trees):
        # Find uninitialized variables
        uninitialized_variable_detector = UninitializedVariableDetector()
        uninitialized_variable_detector.visit(tree)

        # Find illegal flows
        vulnerabilities_copy = deepcopy(vulnerabilities)
        nodeProcessor = NodeProcessor(
            vulnerabilities_copy, uninitialized_variable_detector
        )
        nodeProcessor.visit(tree)

        for illegal_flow in vulnerabilities_copy.get_illegal_flows():
            illegal_flows.add(illegal_flow)

    illegal_flows = list(illegal_flows)

    # Combine illegal flows
    combined_flows = []
    combined_flows_indices = []
    for i in range(len(illegal_flows)):
        for j in range(i + 1, len(illegal_flows)):
            if illegal_flows[i].is_combinable(illegal_flows[j]):
                combined_flows.append(illegal_flows[i].combine(illegal_flows[j]))
                combined_flows_indices += [i, j]

    # Remove combined flows from the original list
    for i in sorted(combined_flows_indices, reverse=True):
        del illegal_flows[i]

    # Add combined flows to the original list
    illegal_flows.extend(combined_flows)

    # Transform illegal flows to JSON
    for i in range(len(illegal_flows)):
        illegal_flows[i] = illegal_flows[i].to_json()

    OUTPUT_FILE = f"output/{SLICE_NAME}.output.json"
    if not os.path.exists("output"):
        os.makedirs("output")
    with open(OUTPUT_FILE, "w") as f:
        f.write(json.dumps(illegal_flows, indent=4) + "\n")
