#!/bin/bash
# Enhanced test runner for LughOS CI/CD
# This script runs various tests and collects the results

set -e

# Create test output directory
mkdir -p test-logs

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run a test and log the result
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local test_log="test-logs/${test_name}.log"
    
    echo -e "${YELLOW}Running test: ${test_name}${NC}"
    echo "Command: ${test_cmd}"
    echo "==================== Test: ${test_name} ====================" > "${test_log}"
    echo "Command: ${test_cmd}" >> "${test_log}"
    echo "Output:" >> "${test_log}"
    
    # Run the test and capture output. The exit status is deliberately
    # ignored for boot tests: the kernel idles forever, so `timeout`
    # always kills QEMU and always returns 124. Judging a boot by the
    # process exit status makes the test unpassable by construction.
    #
    # $3, when given, is a regex the captured output must match, and $4 a
    # regex it must NOT match. That is what actually decides a boot test.
    local require_pattern="${3:-}"
    local forbid_pattern="${4:-}"

    bash -c "${test_cmd}" >> "${test_log}" 2>&1
    local cmd_status=$?

    local verdict=0
    local reason=""

    if [ -n "${require_pattern}" ]; then
        if ! grep -aqE "${require_pattern}" "${test_log}"; then
            verdict=1
            reason="missing required output: ${require_pattern}"
        fi
    elif [ ${cmd_status} -ne 0 ]; then
        # No pattern given — fall back to the exit status.
        verdict=1
        reason="exit status ${cmd_status}"
    fi

    if [ ${verdict} -eq 0 ] && [ -n "${forbid_pattern}" ]; then
        if grep -aqE "${forbid_pattern}" "${test_log}"; then
            verdict=1
            reason="found forbidden output: $(grep -aoE "${forbid_pattern}" "${test_log}" | head -1)"
        fi
    fi

    if [ ${verdict} -eq 0 ]; then
        echo -e "${GREEN}✓ Test ${test_name} passed${NC}"
        echo "RESULT: PASSED" >> "${test_log}"
        return 0
    fi

    echo -e "${RED}✗ Test ${test_name} failed (${reason})${NC}"
    echo "RESULT: FAILED (${reason})" >> "${test_log}"
    # Show the last few lines of the log for quick debugging
    echo "Last lines of log:"
    tail -n 10 "${test_log}"
    return 1
}

# Make sure we have the binaries
if [ ! -f build/x86/lughos.bin ]; then
    echo -e "${RED}Error: x86 kernel binary not found. Run 'make x86' first.${NC}"
    exit 1
fi

# Create a markdown test report
echo "# LughOS Test Results" > test-logs/test-report.md
echo "Generated on: $(date)" >> test-logs/test-report.md
echo "" >> test-logs/test-report.md

# Run our tests
test_results=()

# Count of failed tests — decides this script's exit status. Without it
# the script ended in an unconditional `exit 0`, so a red test reported
# green to any caller that checked the exit code, which is what CI does.
failed_tests=0

# Test 1: Basic QEMU boot test for x86
#
# -nographic already implies -serial stdio. Passing both made QEMU refuse
# to start with "cannot use stdio by multiple character devices", so this
# test could never have passed. It went unnoticed because the x86 build
# was broken, so the script exited earlier on the missing binary.
if run_test "qemu_boot_x86" \
    "timeout 30s qemu-system-i386 -kernel build/x86/lughos.bin -initrd build/x86/user_hello -nographic -no-reboot -display none" \
    "Update test PASS" \
    "EXCEPTION [0-9]+|PANIC|DABORT|PABORT|tests: 0/"; then
    test_results+=("✓ qemu_boot_x86")
else
    test_results+=("✗ qemu_boot_x86")
    failed_tests=$((failed_tests + 1))
fi

# Add test results to the report
echo "## Test Results" >> test-logs/test-report.md
echo "" >> test-logs/test-report.md
for result in "${test_results[@]}"; do
    echo "- ${result}" >> test-logs/test-report.md
done

echo "" >> test-logs/test-report.md
echo "See log files for details." >> test-logs/test-report.md

echo -e "${YELLOW}Tests completed. See test-logs/ directory for details.${NC}"

if [ "${failed_tests}" -ne 0 ]; then
    echo -e "${RED}${failed_tests} test(s) failed${NC}"
    exit 1
fi
exit 0
