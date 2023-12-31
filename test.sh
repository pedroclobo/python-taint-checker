#!/bin/bash

RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'

PY_ANALYSER="./src/py_analyser.py"
TESTS_DIR="./test"

normalize() {
    jq 'sort' | sed 's/"vulnerability": "\([A-Z]\)_[0-9]\+",/"vulnerability": "\1",/'
}


if [ $# -eq 1 ]; then
    TEST_DIR=$TESTS_DIR/$1
    SLICE=$(find "$TEST_DIR" -type f -name '*.py')
    PATTERN=$(find "$TEST_DIR" -type f -name '*.patterns.json')
    OUTPUT_FILE=$(find "$TEST_DIR" -type f -name '*.output.json')
    PROGRAM_OUTPUT_FILE=output/$(basename $OUTPUT_FILE)

    python3 $PY_ANALYSER $SLICE $PATTERN > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo -e "$1: ${RED}FAILED${NC}"
        exit 0
    fi

    VALIDATE_OUTPUT=$(python3 $TESTS_DIR/validate.py -o $PROGRAM_OUTPUT_FILE -t $OUTPUT_FILE)

    if [ $? -ne 0 ]; then
        echo -e "$1: ${RED}FAILED${NC}"
        exit 0
    fi

    EXPECTED_OUTPUT=$(jq . "$OUTPUT_FILE" | normalize)
    PROGRAM_OUTPUT=$(jq . "$PROGRAM_OUTPUT_FILE" | normalize)

    tt=$(echo "$VALIDATE_OUTPUT" | ansi2txt | tr -d '\n' | awk '/WRONG FLOWS\[\]/ && /MISSING FLOWS\[\]/')

    if [ "$tt" != "" ]; then
        echo -e "$1: ${GREEN}PASSED${NC}"
    else
        echo -e "$1: ${RED}FAILED${NC}"
        sdiff <(echo "$PROGRAM_OUTPUT" ) <(echo "$EXPECTED_OUTPUT")
    fi

    exit 0
fi

PASSED=0
TOTAL=0
for test_dir in $(ls -d "$TESTS_DIR"/T*); do
    TOTAL=$((TOTAL+1))

    SLICE=$(find "$test_dir" -type f -name '*.py')
    PATTERN=$(find "$test_dir" -type f -name '*.patterns.json')
    OUTPUT_FILE=$(find "$test_dir" -type f -name '*.output.json')
    PROGRAM_OUTPUT_FILE=output/$(basename $OUTPUT_FILE)

    python3 $PY_ANALYSER $SLICE $PATTERN > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo -e "$(basename $test_dir): ${RED}FAILED${NC}"
        continue
    fi

    VALIDATE_OUTPUT=$(python3 $TESTS_DIR/validate.py -o $PROGRAM_OUTPUT_FILE -t $OUTPUT_FILE)

    if [ $? -ne 0 ]; then
        echo -e "$(basename $test_dir): ${RED}FAILED${NC}"
        continue
    fi

    tt=$(echo "$VALIDATE_OUTPUT" | ansi2txt | tr -d '\n' | awk '/WRONG FLOWS\[\]/ && /MISSING FLOWS\[\]/')

    if [ "$tt" != "" ]; then
        echo -e "$(basename $test_dir): ${GREEN}PASSED${NC}"
        PASSED=$((PASSED+1))
    else
        echo -e "$(basename $test_dir): ${RED}FAILED${NC}"
    fi
done

echo -e "\nPASSED: ${GREEN}$PASSED/$TOTAL${NC}"
