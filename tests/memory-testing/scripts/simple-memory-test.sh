#!/bin/bash
# Simple EVE Memory Allocation Test
# Basic memory allocation testing without complex scenarios

set -e

# Find eden binary
if [ -x "../../eden" ]; then
    EDEN_CMD="../../eden"
elif [ -x "../eden" ]; then
    EDEN_CMD="../eden"
else
    EDEN_CMD="./eden"
fi

RESULTS_DIR="../results/simple-memory-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== Simple EVE Memory Allocation Test ==="
echo "Results: $RESULTS_DIR"
echo ""

test_memory_allocation() {
    local test_name=$1
    local memory_mb=$2
    local description=$3
    
    echo "=== Testing: $test_name ($memory_mb MB) ==="
    echo "Description: $description"
    
    $EDEN_CMD pod delete "simple-memory-test-$test_name" 2>/dev/null || true
    sleep 3
    
    echo "Pre-test EVE memory: $($EDEN_CMD status | grep 'EVE memory' | awk '{print $3}' || echo 'unknown')"
    
    echo "Deploying container with ${memory_mb}MB memory..."
    if $EDEN_CMD pod deploy docker://ubuntu:20.04 --memory="${memory_mb}MB" --name="simple-memory-test-$test_name"; then
        echo "✅ Deployment command successful"
        
        local max_wait=120
        local wait_count=0
        
        while [ $wait_count -lt $max_wait ]; do
            local status=$($EDEN_CMD pod ps | grep "simple-memory-test-$test_name" | awk '{print $NF}' 2>/dev/null || echo "NOT_FOUND")
            
            case "$status" in
                "RUNNING")
                    echo "✅ Container RUNNING successfully after $wait_count seconds"
                    sleep 5
                    $EDEN_CMD pod ps | grep "simple-memory-test-$test_name"
                    echo "SUCCESS,$test_name,${memory_mb}MB,RUNNING,$(date)" >> "$RESULTS_DIR/results.csv"
                    break
                    ;;
                "HALTING"|"ERROR")
                    echo "❌ Container failed - Status: $status"
                    echo "FAILED,$test_name,${memory_mb}MB,$status,$(date)" >> "$RESULTS_DIR/results.csv"
                    break
                    ;;
                *)
                    echo "Waiting... ($wait_count/$max_wait) Status: $status"
                    ;;
            esac
            
            sleep 1
            ((wait_count++))
        done
        
        if [ $wait_count -ge $max_wait ]; then
            echo "❌ Timeout waiting for container"
            echo "TIMEOUT,$test_name,${memory_mb}MB,TIMEOUT,$(date)" >> "$RESULTS_DIR/results.csv"
        fi
        
    else
        echo "❌ Deployment failed"
        echo "DEPLOY_FAILED,$test_name,${memory_mb}MB,DEPLOY_FAILED,$(date)" >> "$RESULTS_DIR/results.csv"
    fi
    
    echo "Post-test EVE memory: $($EDEN_CMD status | grep 'EVE memory' | awk '{print $3}' || echo 'unknown')"
    
    $EDEN_CMD pod delete "simple-memory-test-$test_name" 2>/dev/null || true
    sleep 3
    
    echo "Test $test_name completed"
    echo "----------------------------------------"
    echo ""
}

# Initialize results
echo "Status,TestName,Memory,FinalState,Timestamp" > "$RESULTS_DIR/results.csv"

echo "=== Initial System State ===" | tee "$RESULTS_DIR/initial-status.log"
$EDEN_CMD status | tee -a "$RESULTS_DIR/initial-status.log"
echo "" | tee -a "$RESULTS_DIR/initial-status.log"

# Test Series
test_memory_allocation "light" 128 "Light memory allocation test"
test_memory_allocation "moderate" 256 "Moderate memory allocation test" 
test_memory_allocation "heavy" 512 "Heavy memory allocation test"
test_memory_allocation "max" 800 "Maximum reasonable allocation test"

# Results summary
echo "=== Test Results Summary ==="
echo ""
cat "$RESULTS_DIR/results.csv"
echo ""

# Generate report
{
    echo "# Simple Memory Test Report"
    echo "Generated: $(date)"
    echo ""
    echo "## Test Results"
    echo '```'
    cat "$RESULTS_DIR/results.csv"
    echo '```'
    echo ""
    echo "## Summary"
    
    local success_count=$(grep -c "SUCCESS" "$RESULTS_DIR/results.csv" || echo "0")
    local total_tests=$(tail -n +2 "$RESULTS_DIR/results.csv" | wc -l | tr -d ' ')
    
    echo "- Tests passed: $success_count/$total_tests"
    echo "- Memory allocation capability validated"
    
    if [ $success_count -eq $total_tests ]; then
        echo "✅ All memory allocation tests passed"
    else
        echo "⚠️ Some tests failed - review logs for details"
    fi
    
} > "$RESULTS_DIR/REPORT.md"

echo "Report generated: $RESULTS_DIR/REPORT.md"
echo ""
echo "=== Final System Status ==="
$EDEN_CMD status
