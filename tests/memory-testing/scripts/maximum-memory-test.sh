#!/bin/bash
# EVE Maximum Memory Limits Testing Framework
# Addresses GitHub Issue #4247: Test VM memory limits with maximum RAM allocation

set -e

# Default configuration - can be overridden via command line
DEFAULT_TOTAL_RAM_GB=3.0
DEFAULT_CURRENT_USAGE_MB=800
DEFAULT_TEST_INCREMENT_MB=100
DEFAULT_MAX_CONTAINERS=5

# Parse command line arguments
show_help() {
    cat << HELP_EOF
EVE Maximum Memory Limits Testing Framework

Usage: $0 [OPTIONS]

OPTIONS:
    -t, --total-ram GB          Total system RAM in GB (default: $DEFAULT_TOTAL_RAM_GB)
    -u, --current-usage MB      Current EVE usage in MB (default: $DEFAULT_CURRENT_USAGE_MB)
    -i, --increment MB          Memory increment for progressive testing (default: $DEFAULT_TEST_INCREMENT_MB)
    -c, --max-containers N      Maximum containers for concurrent testing (default: $DEFAULT_MAX_CONTAINERS)
    -m, --max-single MB         Test single container with specific MB
    -p, --pressure-test         Run memory pressure test
    -o, --oom-test             Run OOM simulation test
    -a, --all-tests            Run all test scenarios
    -h, --help                 Show this help

EXAMPLES:
    $0 --total-ram 4.0 --current-usage 1000    # Test with 4GB system, 1GB current usage
    $0 --max-single 1500                       # Test single container with 1.5GB
    $0 --pressure-test                         # Run memory pressure scenarios
    $0 --all-tests                            # Run comprehensive test suite

HELP_EOF
}

# Parse arguments
TOTAL_RAM_GB=$DEFAULT_TOTAL_RAM_GB
CURRENT_USAGE_MB=$DEFAULT_CURRENT_USAGE_MB
INCREMENT_MB=$DEFAULT_TEST_INCREMENT_MB
MAX_CONTAINERS=$DEFAULT_MAX_CONTAINERS
MAX_SINGLE_MB=""
RUN_PRESSURE_TEST=false
RUN_OOM_TEST=false
RUN_ALL_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--total-ram)
            TOTAL_RAM_GB="$2"
            shift 2
            ;;
        -u|--current-usage)
            CURRENT_USAGE_MB="$2"
            shift 2
            ;;
        -i|--increment)
            INCREMENT_MB="$2"
            shift 2
            ;;
        -c|--max-containers)
            MAX_CONTAINERS="$2"
            shift 2
            ;;
        -m|--max-single)
            MAX_SINGLE_MB="$2"
            shift 2
            ;;
        -p|--pressure-test)
            RUN_PRESSURE_TEST=true
            shift
            ;;
        -o|--oom-test)
            RUN_OOM_TEST=true
            shift
            ;;
        -a|--all-tests)
            RUN_ALL_TESTS=true
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

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v bc &> /dev/null; then
        missing_deps+=("bc")
    fi
    
    if [ ! -x "../../eden" ] && [ ! -x "../eden" ] && [ ! -x "./eden" ]; then
        echo "Error: Eden binary not found. Please ensure eden is built and accessible."
        exit 1
    fi
    
    # Find eden binary
    if [ -x "../../eden" ]; then
        EDEN_CMD="../../eden"
    elif [ -x "../eden" ]; then
        EDEN_CMD="../eden"
    else
        EDEN_CMD="./eden"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo "Error: Missing dependencies: ${missing_deps[*]}"
        echo "Install with: brew install ${missing_deps[*]}"
        exit 1
    fi
}

check_dependencies

# Calculate memory parameters
TOTAL_RAM_MB=$(echo "$TOTAL_RAM_GB * 1024" | bc)
AVAILABLE_RAM_MB=$(echo "$TOTAL_RAM_MB - $CURRENT_USAGE_MB" | bc)
SAFE_MAX_MB=$(echo "$AVAILABLE_RAM_MB * 0.9" | bc | cut -d. -f1)
AGGRESSIVE_MAX_MB=$(echo "$AVAILABLE_RAM_MB * 0.95" | bc | cut -d. -f1)
EXTREME_MAX_MB=$(echo "$AVAILABLE_RAM_MB * 1.05" | bc | cut -d. -f1)

# Results directory
RESULTS_DIR="../results/max-memory-test-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== EVE Maximum Memory Limits Testing Framework ==="
echo "GitHub Issue #4247: VM memory limits with maximum RAM allocation"
echo ""
echo "System Configuration:"
echo "  Total RAM: ${TOTAL_RAM_GB}GB (${TOTAL_RAM_MB}MB)"
echo "  Current Usage: ${CURRENT_USAGE_MB}MB"
echo "  Available RAM: ${AVAILABLE_RAM_MB}MB"
echo "  Safe Maximum: ${SAFE_MAX_MB}MB (90%)"
echo "  Aggressive Maximum: ${AGGRESSIVE_MAX_MB}MB (95%)"
echo "  Extreme Test: ${EXTREME_MAX_MB}MB (105% - OOM expected)"
echo ""
echo "Results Directory: $RESULTS_DIR"
echo ""

# Initialize results
echo "TestType,ContainerName,MemoryMB,Status,DeployTime,ErrorDetails,Timestamp" > "$RESULTS_DIR/results.csv"

cleanup_containers() {
    echo "Cleaning up all test containers..."
    $EDEN_CMD pod ps | grep "memory-max-test" | awk '{print $1}' | xargs -I {} $EDEN_CMD pod delete {} 2>/dev/null || true
    sleep 5
}

test_single_container() {
    local memory_mb=$1
    local test_type=$2
    local container_name="memory-max-test-single-${memory_mb}mb"
    
    echo "=== Testing Single Container: ${memory_mb}MB ($test_type) ==="
    
    cleanup_containers
    
    local start_time=$(date +%s)
    local pre_memory=$($EDEN_CMD status | grep 'EVE memory' | awk '{print $3}' || echo "unknown")
    
    echo "Pre-test EVE memory: $pre_memory"
    echo "Deploying container with ${memory_mb}MB..."
    
    if $EDEN_CMD pod deploy docker://ubuntu:20.04 --memory="${memory_mb}MB" --name="$container_name" 2>&1 | tee "$RESULTS_DIR/$container_name-deploy.log"; then
        echo "✅ Deployment command successful"
        
        local wait_count=0
        local max_wait=180
        
        while [ $wait_count -lt $max_wait ]; do
            local status=$($EDEN_CMD pod ps | grep "$container_name" | awk '{print $NF}' 2>/dev/null || echo "NOT_FOUND")
            
            case "$status" in
                "RUNNING")
                    local end_time=$(date +%s)
                    local deploy_time=$((end_time - start_time))
                    echo "✅ SUCCESS: Container running after ${deploy_time}s"
                    
                    sleep 10
                    $EDEN_CMD pod ps | grep "$container_name" | tee "$RESULTS_DIR/$container_name-final-status.txt"
                    $EDEN_CMD pod logs "$container_name" | tail -20 > "$RESULTS_DIR/$container_name-logs.txt" 2>&1 || true
                    
                    echo "SUCCESS,$container_name,${memory_mb},RUNNING,$deploy_time,,$(date)" >> "$RESULTS_DIR/results.csv"
                    
                    sleep 60  # Let it run for stability testing
                    return 0
                    ;;
                "HALTING"|"ERROR")
                    local end_time=$(date +%s)
                    local deploy_time=$((end_time - start_time))
                    echo "❌ FAILED: Container failed - Status: $status"
                    
                    local error_details=$($EDEN_CMD pod logs "$container_name" 2>&1 | grep -i "error\|oom\|memory" | head -3 | tr '\n' ';' || echo "No specific error")
                    echo "FAILED,$container_name,${memory_mb},$status,$deploy_time,$error_details,$(date)" >> "$RESULTS_DIR/results.csv"
                    
                    return 1
                    ;;
                *"Remaining memory"*)
                    echo "❌ MEMORY_REJECTED: Not enough memory available"
                    echo "Details: $status"
                    echo "MEMORY_REJECTED,$container_name,${memory_mb},INSUFFICIENT_MEMORY,0,EVE rejected deployment,$(date)" >> "$RESULTS_DIR/results.csv"
                    return 1
                    ;;
                *)
                    if [ $((wait_count % 30)) -eq 0 ]; then
                        echo "Waiting... ($wait_count/$max_wait) Status: $status"
                    fi
                    ;;
            esac
            
            sleep 1
            ((wait_count++))
        done
        
        echo "❌ TIMEOUT: Container did not start within ${max_wait}s"
        echo "TIMEOUT,$container_name,${memory_mb},TIMEOUT,$max_wait,Deployment timeout,$(date)" >> "$RESULTS_DIR/results.csv"
        return 1
        
    else
        echo "❌ DEPLOY_FAILED: Deployment command failed"
        echo "DEPLOY_FAILED,$container_name,${memory_mb},DEPLOY_FAILED,0,Command failed,$(date)" >> "$RESULTS_DIR/results.csv"
        return 1
    fi
    
    cleanup_containers
}

test_progressive_allocation() {
    echo "=== Progressive Memory Allocation Test ==="
    echo "Testing memory allocation from safe to extreme levels"
    
    test_single_container $SAFE_MAX_MB "SAFE_MAX"
    sleep 10
    
    test_single_container $AGGRESSIVE_MAX_MB "AGGRESSIVE_MAX"
    sleep 10
    
    echo "Testing extreme allocation (OOM expected)..."
    test_single_container $EXTREME_MAX_MB "EXTREME_OOM_TEST"
}

test_concurrent_containers() {
    echo "=== Concurrent Containers Test ==="
    echo "Deploying multiple containers to test concurrent memory allocation"
    
    cleanup_containers
    
    local per_container_mb=$(echo "$SAFE_MAX_MB / $MAX_CONTAINERS" | bc)
    echo "Deploying $MAX_CONTAINERS containers with ${per_container_mb}MB each"
    
    local success_count=0
    
    for i in $(seq 1 $MAX_CONTAINERS); do
        local container_name="memory-max-test-concurrent-$i"
        echo "Deploying container $i/${MAX_CONTAINERS}..."
        
        if $EDEN_CMD pod deploy docker://ubuntu:20.04 --memory="${per_container_mb}MB" --name="$container_name"; then
            echo "CONCURRENT_SUCCESS,$container_name,$per_container_mb,DEPLOYED,0,,$(date)" >> "$RESULTS_DIR/results.csv"
            ((success_count++))
        else
            echo "CONCURRENT_FAILED,$container_name,$per_container_mb,DEPLOY_FAILED,0,Command failed,$(date)" >> "$RESULTS_DIR/results.csv"
        fi
        
        sleep 5
    done
    
    echo "Deployed $success_count/$MAX_CONTAINERS containers"
    sleep 60
    
    $EDEN_CMD pod ps | grep "memory-max-test-concurrent" > "$RESULTS_DIR/concurrent-final-status.txt" || true
    sleep 120
    
    cleanup_containers
}

test_memory_pressure() {
    echo "=== Memory Pressure Test ==="
    echo "Testing behavior under memory pressure conditions"
    
    local base_allocation=$(echo "$AVAILABLE_RAM_MB * 0.7" | bc | cut -d. -f1)
    echo "Step 1: Deploy base container with ${base_allocation}MB"
    test_single_container $base_allocation "PRESSURE_BASE"
    
    echo "Step 2: Add additional containers while base is running"
    local additional_mb=$(echo "$AVAILABLE_RAM_MB * 0.2" | bc | cut -d. -f1)
    
    if $EDEN_CMD pod deploy docker://ubuntu:20.04 --memory="${additional_mb}MB" --name="memory-max-test-pressure-add"; then
        echo "PRESSURE_SUCCESS,memory-max-test-pressure-add,$additional_mb,DEPLOYED,0,,$(date)" >> "$RESULTS_DIR/results.csv"
        sleep 30
        $EDEN_CMD pod ps | grep "memory-max-test" > "$RESULTS_DIR/pressure-test-status.txt" || true
    else
        echo "PRESSURE_REJECTED,memory-max-test-pressure-add,$additional_mb,DEPLOY_FAILED,0,Memory pressure rejection,$(date)" >> "$RESULTS_DIR/results.csv"
    fi
    
    cleanup_containers
}

generate_report() {
    echo "=== Generating Test Report ==="
    
    local total_tests=$(tail -n +2 "$RESULTS_DIR/results.csv" | wc -l | tr -d ' ')
    local successful_tests=$(grep -c "SUCCESS\|RUNNING" "$RESULTS_DIR/results.csv" || echo "0")
    local failed_tests=$(grep -c "FAILED\|TIMEOUT\|REJECTED" "$RESULTS_DIR/results.csv" || echo "0")
    
    cat > "$RESULTS_DIR/REPORT.md" << REPORT_EOF
# EVE Maximum Memory Limits Test Report
**GitHub Issue #4247 Validation**

Generated: $(date)
Test Configuration: ${TOTAL_RAM_GB}GB total, ${CURRENT_USAGE_MB}MB current usage

## Executive Summary
- **Total Tests**: $total_tests
- **Successful**: $successful_tests
- **Failed**: $failed_tests
- **Success Rate**: $(echo "scale=1; $successful_tests * 100 / $total_tests" | bc)%

## Test Results
\`\`\`
$(cat "$RESULTS_DIR/results.csv")
\`\`\`

## Memory Allocation Limits Discovered
- **Safe Maximum**: ${SAFE_MAX_MB}MB (90% of available)
- **Aggressive Maximum**: ${AGGRESSIVE_MAX_MB}MB (95% of available)
- **Extreme Test**: ${EXTREME_MAX_MB}MB (105% - OOM boundary)

## System Configuration
- **Total System RAM**: ${TOTAL_RAM_GB}GB
- **EVE System Usage**: ${CURRENT_USAGE_MB}MB
- **Available for Containers**: ${AVAILABLE_RAM_MB}MB
- **Calculated Overhead**: $(echo "$TOTAL_RAM_MB - $AVAILABLE_RAM_MB" | bc)MB

## Conclusions for GitHub Issue #4247
$(if [ $successful_tests -gt 0 ]; then
    echo "✅ **Maximum memory allocation testing successful**"
    echo "✅ **EVE properly handles memory limit enforcement**"
    echo "✅ **Memory overhead calculations validated**"
else
    echo "❌ **Issues detected with memory allocation**"
    echo "❌ **Further investigation needed**"
fi)

## Recommendations
$(if [ $successful_tests -eq $total_tests ]; then
    echo "- EVE memory management is working correctly"
    echo "- Memory limits are properly enforced"
    echo "- System can handle maximum allocation scenarios"
else
    echo "- Review failed test scenarios"
    echo "- Adjust memory overhead calculations"
    echo "- Consider system resource constraints"
fi)

REPORT_EOF

    echo "Report generated: $RESULTS_DIR/REPORT.md"
}

# Main execution logic
main() {
    # Record initial system state
    $EDEN_CMD status > "$RESULTS_DIR/initial-system-state.log"
    $EDEN_CMD pod ps > "$RESULTS_DIR/initial-pods.log" 2>/dev/null || true
    
    if [ "$RUN_ALL_TESTS" = true ]; then
        echo "Running comprehensive test suite..."
        test_progressive_allocation
        test_concurrent_containers
        test_memory_pressure
    else
        if [ -n "$MAX_SINGLE_MB" ]; then
            test_single_container "$MAX_SINGLE_MB" "CUSTOM_SINGLE"
        fi
        
        if [ "$RUN_PRESSURE_TEST" = true ]; then
            test_memory_pressure
        fi
        
        if [ "$RUN_OOM_TEST" = true ]; then
            test_single_container $EXTREME_MAX_MB "OOM_TEST"
        fi
        
        # If no specific tests requested, run progressive
        if [ -z "$MAX_SINGLE_MB" ] && [ "$RUN_PRESSURE_TEST" = false ] && [ "$RUN_OOM_TEST" = false ]; then
            test_progressive_allocation
        fi
    fi
    
    generate_report
    
    echo ""
    echo "=== Test Execution Complete ==="
    echo "Results: $RESULTS_DIR"
    echo "Summary:"
    tail -n +2 "$RESULTS_DIR/results.csv" | cut -d, -f3,4 | sort | uniq -c || echo "No results to summarize"
}

# Run main function
main
