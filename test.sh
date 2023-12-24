#!/bin/bash

RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'

PY_ANALYSER_PATH="./src/py_analyser.py"
TEST_DIR="./test"

normalize() {
    jq 'sort' | sed 's/"vulnerability": "\([A-Z]\)_[0-9]\+",/"vulnerability": "\1",/'
}

[ -d "output" ] || mkdir output

if [ "$#" == 1 ]; then
    SLICE_FILE="$TEST_DIR/slices/$1.py"
    PATTERN_FILE="$TEST_DIR/patterns/$1.patterns.json"
    OUTPUT_FILE="$TEST_DIR/outputs/$1.output.json"
    PROGRAM_OUTPUT_FILE="./output/$1.output.json"

    python3 $PY_ANALYSER_PATH $SLICE_FILE $PATTERN_FILE > /dev/null 2>&1

    EXPECTED_OUTPUT=$(jq . "$OUTPUT_FILE" | normalize)
    PROGRAM_OUTPUT=$(jq . "$PROGRAM_OUTPUT_FILE" | normalize)

    if diff <(echo "$PROGRAM_OUTPUT") <(echo "$EXPECTED_OUTPUT") &> /dev/null; then
        echo -e "${GREEN}PASSED${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        sdiff <(echo "$PROGRAM_OUTPUT" ) <(echo "$EXPECTED_OUTPUT")
    fi

    exit 0
fi

for SLICE_FILE in $TEST_DIR/slices/*.py; do
    SLICE_NAME=$(basename $SLICE_FILE .py)
    PATTERN_FILE="$TEST_DIR/patterns/$SLICE_NAME.patterns.json"
    OUTPUT_FILE="$TEST_DIR/outputs/$SLICE_NAME.output.json"
    PROGRAM_OUTPUT_FILE="./output/$SLICE_NAME.output.json"

    python3 $PY_ANALYSER_PATH $SLICE_FILE $PATTERN_FILE > /dev/null 2>&1

    EXPECTED_OUTPUT=$(jq . "$OUTPUT_FILE" | normalize)
    PROGRAM_OUTPUT=$(jq . "$PROGRAM_OUTPUT_FILE" | normalize)

    if diff <(echo "$PROGRAM_OUTPUT") <(echo "$EXPECTED_OUTPUT") &> /dev/null; then
        echo -e "${GREEN}PASSED: ${NC}$SLICE_NAME"
    else
        echo -e "${RED}FAILED: ${NC}$SLICE_NAME"
    fi
done
