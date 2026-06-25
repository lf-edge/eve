#!/bin/bash
# EVE Memory Boundary Finder
# Finds the precise memory allocation boundary using binary search

set -e

# Find eden binary
if [ -x "../../eden" ]; then
    EDEN_CMD="../../eden"
elif [ -x "../eden" ]; then
    EDEN_CMD="../eden"
else
    EDEN_CMD="./eden"
fi

# Default parameters
START_MB=1000
END_MB=3000
PRECISION_MB=10
TIMEOUT_SECONDS=120

# Global variables for tracking state
last_success=0
found_failure=false

show_help() {
    cat << 'HELP_EOF'
EVE Memory Boundary Finder

Usage: $0 [OPTIONS]

OPTIONS:
    --start MB              Starting memory value for search (default: 1000)
    --end MB                Ending memory value for search (default: 3000)
    --precision MB          Search precision in MB (default: 10)
    --timeout SECONDS       Timeout for each test (default: 120)
    --auto-detect          Auto-detect search range from system
    -h, --help             Show this help

EXAMPLES:
    $0 --start 1500 --end 2500 --precision 5
    $0 --auto-detect --precision 10

HELP_EOF
}

# Function to generate the final report
generate_final_report() {
    {
        echo "# Memory Boundary Discovery Report"
        echo "Generated: $(date)"
        echo ""
        echo "## Search Parameters"
        echo "- Search range: ${START_MB}MB to ${END_MB}MB"
        echo "- Precision: ${PRECISION_MB}MB"
        echo "- Timeout per test: ${TIMEOUT_SECONDS}s"
        echo ""
        echo "## Results"
        if [ $last_success -gt 0 ] && [ "$found_failure" = true ]; then
            echo "**Maximum Allocation Discovered: ${last_success}MB**"
            echo ""
            echo "- Highest successful allocation: ${last_success}MB"
            echo "- Search precision: ±${PRECISION_MB}MB"
            echo "- Status: ✅ Boundary found"

            # Extract the actual memory limit from error messages if available
            if grep -q "Remaining memory bytes" "$RESULTS_DIR/boundary-tests.csv"; then
                local remaining_bytes=$(grep "Remaining memory bytes" "$RESULTS_DIR/boundary-tests.csv" | tail -1 | grep -o "Remaining memory bytes [0-9]*" | awk '{print $4}')
                if [ -n "$remaining_bytes" ]; then
                    local remaining_mb=$(echo "scale=2; $remaining_bytes / 1048576" | bc)
                    echo "- Actual available memory: ${remaining_mb}MB"
                fi
            fi
        elif [ "$found_failure" = false ] && [ $last_success -gt 0 ]; then
            echo "**All allocations succeeded up to ${last_success}MB**"
            echo ""
            echo "- All tests passed up to: ${last_success}MB"
            echo "- Status: ⚠️ Upper boundary not found"
            echo "- Recommendation: Run with higher --end value"
        else
            echo "**No successful allocations found**"
            echo ""
            echo "- Status: ❌ Boundary not found in range"
            echo "- Recommendation: Check system resources or adjust search range"
        fi
        echo ""
        echo "## Test Summary"
        local total_tests=$(tail -n +2 "$RESULTS_DIR/boundary-tests.csv" | wc -l | tr -d ' ')
        local success_tests=$(grep -c "SUCCESS" "$RESULTS_DIR/boundary-tests.csv" || echo "0")
        local failed_tests=$(grep -c "INSUFFICIENT_MEMORY\|FAILED\|TIMEOUT\|NEVER_APPEARED" "$RESULTS_DIR/boundary-tests.csv" || echo "0")
        echo "- Total tests: $total_tests"
        echo "- Successful: $success_tests"
        echo "- Failed: $failed_tests"
        echo ""
        echo "## All Test Results"
        echo '```csv'
        cat "$RESULTS_DIR/boundary-tests.csv"
        echo '```'
    } > "$RESULTS_DIR/BOUNDARY-REPORT.md"

    echo ""
    echo "Detailed report: $RESULTS_DIR/BOUNDARY-REPORT.md"
}

# Signal handler to generate report on interrupt
cleanup_and_report() {
    echo ""
    echo "Interrupted! Generating report with current results..."

    # Clean up any running containers
    echo "Cleaning up test containers..."
    $EDEN_CMD pod ps | grep "boundary-test-" | awk '{print $1}' | xargs -I {} $EDEN_CMD pod delete {} 2>/dev/null || true

    generate_final_report
    exit 0
}

# Trap Ctrl+C
trap cleanup_and_report INT

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --start)
            START_MB="$2"
            shift 2
            ;;
        --end)
            END_MB="$2"
            shift 2
            ;;
        --precision)
            PRECISION_MB="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --auto-detect)
            AUTO_DETECT=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$AUTO_DETECT" = true ]; then
    echo "Auto-detecting system parameters..."
    # Extract current memory usage and calculate reasonable bounds
    current_usage=$($EDEN_CMD status | grep 'EVE memory' | awk '{print $3}' | cut -d'/' -f1 | sed 's/MB//' | tr -d ' ')
    total_ram=$($EDEN_CMD status | grep 'EVE memory' | awk '{print $3}' | cut -d'/' -f2 | sed 's/GB//' | tr -d ' ')

    if [ -n "$current_usage" ] && [ -n "$total_ram" ]; then
        total_mb=$(echo "$total_ram * 1024" | bc)
        available_mb=$(echo "$total_mb - $current_usage" | bc)
        START_MB=$(echo "$available_mb * 0.8" | bc | cut -d. -f1)
        END_MB=$(echo "$available_mb * 1.5" | bc | cut -d. -f1)  # Test up to 150% to ensure we find the boundary
        echo "Detected: Total RAM: ${total_mb}MB, Current usage: ${current_usage}MB"
        echo "Setting search range: ${START_MB}MB to ${END_MB}MB"
    fi
fi

RESULTS_DIR="../results/boundary-search-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== EVE Memory Boundary Finder ==="
echo "Search range: ${START_MB}MB to ${END_MB}MB"
echo "Precision: ${PRECISION_MB}MB"
echo "Results: $RESULTS_DIR"
echo ""

# Test function
test_allocation() {
    local memory_mb=$1
    local container_name="boundary-test-${memory_mb}mb"

    echo "Testing ${memory_mb}MB allocation..."

    # Clean up any existing container
    $EDEN_CMD pod delete "$container_name" 2>/dev/null || true
    sleep 2

    # Deploy container
    if ! $EDEN_CMD pod deploy docker://ubuntu:20.04 --memory="${memory_mb}MB" --name="$container_name" >/dev/null 2>&1; then
        echo "DEPLOY_FAILED,$memory_mb,$(date)" >> "$RESULTS_DIR/boundary-tests.csv"
        return 1
    fi

    # Wait for result - give it more time to actually start
    local wait_count=0
    local container_found=false

    while [ $wait_count -lt $TIMEOUT_SECONDS ]; do
        local pod_line=$($EDEN_CMD pod ps | grep "$container_name" 2>/dev/null || echo "")

        if [ -n "$pod_line" ]; then
            container_found=true
            local status=$(echo "$pod_line" | awk '{print $NF}')

            # Also check for INSTALLED state with error message
            if echo "$pod_line" | grep -q "Remaining memory"; then
                echo "❌ ${memory_mb}MB: INSUFFICIENT_MEMORY"
                local error_msg=$(echo "$pod_line" | grep -o "Remaining memory.*")
                echo "Error: $error_msg"
                echo "INSUFFICIENT_MEMORY,$memory_mb,$(date),\"$error_msg\"" >> "$RESULTS_DIR/boundary-tests.csv"
                $EDEN_CMD pod delete "$container_name" >/dev/null 2>&1 || true
                return 1
            fi

            case "$status" in
                "RUNNING")
                    echo "✅ ${memory_mb}MB: SUCCESS"
                    echo "SUCCESS,$memory_mb,$(date)" >> "$RESULTS_DIR/boundary-tests.csv"
                    $EDEN_CMD pod delete "$container_name" >/dev/null 2>&1 || true
                    return 0
                    ;;
                "HALTING"|"ERROR"|"BROKEN")
                    echo "❌ ${memory_mb}MB: FAILED - Status: $status"
                    echo "FAILED,$memory_mb,$(date),\"Status: $status\"" >> "$RESULTS_DIR/boundary-tests.csv"
                    $EDEN_CMD pod delete "$container_name" >/dev/null 2>&1 || true
                    return 1
                    ;;
                "INSTALLED")
                    # Keep waiting - might still be starting
                    ;;
                *)
                    # Keep waiting for other states
                    ;;
            esac
        fi

        if [ $((wait_count % 10)) -eq 0 ] && [ $wait_count -gt 0 ]; then
            echo "  Still waiting... ($wait_count/$TIMEOUT_SECONDS)"
        fi

        sleep 1
        ((wait_count++))
    done

    if [ "$container_found" = false ]; then
        echo "❌ ${memory_mb}MB: Container never appeared in pod list"
        echo "NEVER_APPEARED,$memory_mb,$(date)" >> "$RESULTS_DIR/boundary-tests.csv"
    else
        echo "⏰ ${memory_mb}MB: TIMEOUT"
        echo "TIMEOUT,$memory_mb,$(date)" >> "$RESULTS_DIR/boundary-tests.csv"
    fi

    $EDEN_CMD pod delete "$container_name" >/dev/null 2>&1 || true
    return 1
}

# Initialize results
echo "Status,MemoryMB,Timestamp,Details" > "$RESULTS_DIR/boundary-tests.csv"

# Binary search for boundary
low=$START_MB
high=$END_MB

echo "Starting binary search..."

while [ $((high - low)) -gt $PRECISION_MB ]; do
    mid=$(((low + high) / 2))

    echo ""
    echo "Testing boundary: low=$low, mid=$mid, high=$high"

    if test_allocation $mid; then
        # Success - try higher
        last_success=$mid
        low=$mid
    else
        # Failed - try lower
        found_failure=true
        high=$mid
    fi
done

echo ""
echo "=== Boundary Search Complete ==="

# Only run confirmation if we actually found a failure point
if [ "$found_failure" = true ] && [ $last_success -gt 0 ]; then
    echo ""
    echo "Confirming boundary around ${last_success}MB..."

    confirmation_count=0
    max_confirmations=4

    for offset in -20 -10 10 20; do
        test_mb=$((last_success + offset))
        if [ $test_mb -gt 0 ] && [ $test_mb -lt $END_MB ] && [ $confirmation_count -lt $max_confirmations ]; then
            # Add a timeout wrapper
            timeout 60 bash -c "$(declare -f test_allocation); test_allocation $test_mb" || {
                echo "⏰ Test timed out for ${test_mb}MB"
                echo "CONFIRMATION_TIMEOUT,$test_mb,$(date)" >> "$RESULTS_DIR/boundary-tests.csv"
            }
            ((confirmation_count++))
        fi
    done

    echo ""
    echo "🎯 DISCOVERED BOUNDARY: ${last_success}MB (±${PRECISION_MB}MB)"
    echo ""
    echo "Results:"
    echo "  Maximum successful allocation: ${last_success}MB"
    echo "  Search precision: ±${PRECISION_MB}MB"
    echo "  Recommendation: Use ${last_success}MB or less for reliable allocation"
elif [ "$found_failure" = false ]; then
    echo ""
    echo "⚠️  All allocations succeeded up to ${last_success}MB!"
    echo "The actual memory limit is higher than the test range."
    echo "Try running with a higher --end value."
else
    echo "❌ No successful allocations found in range ${START_MB}MB to ${END_MB}MB"
fi

# Generate the final report
generate_final_report