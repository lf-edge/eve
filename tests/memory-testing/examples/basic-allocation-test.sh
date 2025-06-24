#!/bin/bash
# Example: Basic Memory Allocation Test
# Tests standard memory allocations to verify EVE functionality

cd "$(dirname "$0")/.."

echo "=== Basic EVE Memory Allocation Test ==="
echo "Testing standard memory allocations..."

# Run simple memory test
./scripts/simple-memory-test.sh

echo ""
echo "Basic test completed. Check results/ directory for detailed output."
