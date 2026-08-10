#!/bin/bash
#
# Test runner script for CTF-toolkit
# Inspired by project-forge testing methodology
#

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Banner
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     CTF-Toolkit E2E Test Runner          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check if virtual environment exists
if [ ! -d ".venv" ] && [ ! -d "venv" ]; then
    echo -e "${YELLOW}⚠ No virtual environment found${NC}"
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements-test.txt
else
    if [ -d ".venv" ]; then
        source .venv/bin/activate
    else
        source venv/bin/activate
    fi
fi

# Install/update test dependencies
echo -e "${BLUE}📦 Checking test dependencies...${NC}"
pip install -q -r requirements-test.txt

# Parse command line arguments
TEST_TYPE=${1:-all}
COVERAGE=${2:-false}

echo ""
echo -e "${GREEN}🧪 Running tests: ${TEST_TYPE}${NC}"
echo ""

# Run tests based on type
case $TEST_TYPE in
    "e2e"|"all")
        echo -e "${BLUE}Running E2E tests...${NC}"
        if [ "$COVERAGE" = "coverage" ]; then
            pytest tests/ -v --cov=. --cov-report=html --cov-report=term
        else
            pytest tests/ -v
        fi
        ;;
    "flask")
        echo -e "${BLUE}Running Flask server tests...${NC}"
        pytest tests/test_e2e_flask_server.py -v
        ;;
    "listener")
        echo -e "${BLUE}Running listener tests...${NC}"
        pytest tests/test_e2e_listener.py -v
        ;;
    "security")
        echo -e "${BLUE}Running security tests...${NC}"
        pytest tests/ -v -m security
        bandit -r . -f json -o bandit-report.json || true
        echo -e "${GREEN}Security scan complete. Check bandit-report.json${NC}"
        ;;
    "quick")
        echo -e "${BLUE}Running quick tests (excluding slow)...${NC}"
        pytest tests/ -v -m "not slow"
        ;;
    "help")
        echo "Usage: ./run_tests.sh [test_type] [coverage]"
        echo ""
        echo "Test types:"
        echo "  all       - Run all tests (default)"
        echo "  e2e       - Run all E2E tests"
        echo "  flask     - Run Flask server tests only"
        echo "  listener  - Run listener tests only"
        echo "  security  - Run security tests and scans"
        echo "  quick     - Run quick tests (exclude slow)"
        echo "  help      - Show this help message"
        echo ""
        echo "Coverage:"
        echo "  coverage  - Generate coverage report"
        echo ""
        echo "Examples:"
        echo "  ./run_tests.sh                  # Run all tests"
        echo "  ./run_tests.sh flask            # Run Flask tests only"
        echo "  ./run_tests.sh all coverage     # Run all tests with coverage"
        echo "  ./run_tests.sh security         # Run security tests"
        exit 0
        ;;
    *)
        echo -e "${RED}Unknown test type: $TEST_TYPE${NC}"
        echo "Run './run_tests.sh help' for usage information"
        exit 1
        ;;
esac

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Tests passed successfully!${NC}"
else
    echo -e "${RED}❌ Tests failed with exit code: $TEST_EXIT_CODE${NC}"
fi
echo ""

exit $TEST_EXIT_CODE
