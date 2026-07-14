#!/bin/bash
# Example: Production Environment Validation
# Comprehensive testing for production systems

cd "$(dirname "$0")/.."

echo "=== Production Environment Validation ==="
echo "Running comprehensive memory allocation tests..."

# Get current system usage
current_usage=$(../../eden status | grep 'EVE memory' | awk '{print $3}' | cut -d'/' -f1 | sed 's/MB//' | tr -d ' ')
total_ram=$(../../eden status | grep 'EVE memory' | awk '{print $3}' | cut -d'/' -f2 | sed 's/GB//' | tr -d ' ')

echo "Detected system: ${total_ram}GB total, ${current_usage}MB current usage"

# Run comprehensive tests
./scripts/maximum-memory-test.sh \
  --total-ram "$total_ram" \
  --current-usage "$current_usage" \
  --all-tests

echo ""
echo "Production validation completed. Review results for production readiness assessment."
