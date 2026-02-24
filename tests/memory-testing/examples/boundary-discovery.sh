#!/bin/bash
# Example: Discover Memory Allocation Boundaries
# Finds the exact maximum memory allocation limit

cd "$(dirname "$0")/.."

echo "=== Memory Boundary Discovery ==="
echo "Finding maximum memory allocation limit..."

# Auto-detect system parameters and find boundary
./scripts/boundary-finder.sh --auto-detect --precision 10

echo ""
echo "Boundary discovery completed. Check results/ directory for detailed report."
