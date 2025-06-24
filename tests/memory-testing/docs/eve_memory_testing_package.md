# EVE Memory Limits Testing Framework

A comprehensive testing framework for validating EVE OS memory management capabilities and discovering memory allocation boundaries.

## Purpose

This framework addresses [GitHub Issue #4247](https://github.com/lf-edge/eve/issues/4247) by providing automated testing for:

- **Maximum memory allocation limits** - Discover EVE's actual memory boundaries
- **Memory overhead validation** - Measure system overhead vs. available container memory  
- **Memory pressure scenarios** - Test behavior under resource constraints
- **OOM boundary testing** - Validate graceful handling of over-allocation
- **Concurrent allocation testing** - Test multiple container memory allocation

## Prerequisites

### System Requirements
- **EVE OS** running with embedded Adam controller (Eden framework)
- **At least 3GB RAM** allocated to EVE
- **Eden CLI** installed and configured
- **Terraform** >= 1.0
- **bc calculator** for mathematical operations

### Software Dependencies

```bash
# Install required tools
terraform bc jq

# Verify Eden is working
cd /path/to/your/eden
./eden status
```

### EVE System Prerequisites
- EVE OS running with embedded Adam controller
- Registry, Redis, and EServer components running
- At least one successful container deployment (to verify system functionality)
- Telegraf monitoring (recommended)

## Framework Structure

```
memory-testing/
├── README.md                           # This documentation
├── scripts/
│   ├── maximum-memory-test.sh          # Main testing script
│   ├── simple-memory-test.sh           # Basic allocation testing
│   └── boundary-finder.sh              # Precise boundary detection
├── terraform/
│   ├── main.tf                         # Terraform configuration
│   ├── terraform.tfvars.example        # Configuration template
│   ├── templates/
│   │   ├── eden-deploy.tpl            # Eden deployment template
│   │   ├── monitoring-config.tpl       # Monitoring configuration
│   │   └── test-runner.tpl            # Test execution template
│   └── outputs.tf                     # Terraform outputs
├── examples/
│   ├── basic-allocation-test.sh        # Example: Basic testing
│   ├── boundary-discovery.sh           # Example: Find exact limits
│   └── production-validation.sh        # Example: Production testing
└── results/                           # Test results directory (created during execution)
    └── [timestamp]/                   # Results organized by test run
        ├── results.csv                # Detailed test results
        ├── REPORT.md                  # Executive summary
        └── *.log                      # Individual test logs
```

## Quick Start

### 1. Setup
```bash
# Clone or download the memory-testing framework
cd /path/to/your/eden
git clone [memory-testing-framework] memory-testing
cd memory-testing

# Configure for your system
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform.tfvars with your system specifications

# Initialize Terraform
cd terraform
terraform init
terraform apply
cd ..
```

### 2. Basic Memory Allocation Test
```bash
# Test basic memory allocation capabilities
./scripts/simple-memory-test.sh

# Results will be in results/memory-allocation-[timestamp]/
```

### 3. Find Memory Boundaries
```bash
# Discover your system's exact memory limits
./scripts/maximum-memory-test.sh --all-tests

# Or test specific allocation
./scripts/maximum-memory-test.sh --max-single 2048
```

### 4. Boundary Discovery
```bash
# Find precise memory allocation boundary
./scripts/boundary-finder.sh --start 1500 --end 2500 --increment 50
```

## Usage Examples

### Example 1: Basic System Validation
```bash
# Test if EVE can handle standard memory allocations
./scripts/simple-memory-test.sh

# Expected output:
# ✅ Light (128MB): SUCCESS
# ✅ Moderate (256MB): SUCCESS  
# ✅ Heavy (512MB): SUCCESS
# ✅ Maximum (800MB): SUCCESS
```

### Example 2: Discover Memory Boundaries
```bash
# Find your system's maximum allocation limit
./scripts/maximum-memory-test.sh --total-ram 4.0 --current-usage 1000 --all-tests

# This will test:
# - Safe allocation (90% of available)
# - Aggressive allocation (95% of available)
# - Over-allocation (105% - should fail)
# - Concurrent containers
# - Memory pressure scenarios
```

### Example 3: Production System Validation
```bash
# Test production readiness with specific parameters
./scripts/maximum-memory-test.sh \
  --total-ram 8.0 \
  --current-usage 2000 \
  --max-containers 10 \
  --pressure-test

# Results indicate if system can handle production workloads
```

### Example 4: Precise Boundary Detection
```bash
# Find exact allocation limit within 10MB precision
./scripts/boundary-finder.sh \
  --start 1800 \
  --end 2200 \
  --increment 10 \
  --precision 5

# Output: "Maximum allocation: 2018MB ±5MB"
```

## Configuration

### System Configuration (terraform.tfvars)
```hcl
# Your EVE system specifications
eve_system_ram_gb      = 4.0    # Total RAM allocated to EVE
eve_current_usage_mb   = 1200   # Current system usage (from ./eden status)
test_duration_minutes  = 5      # How long to run each test
max_test_containers    = 5      # Maximum concurrent containers to test

# Test parameters
safe_allocation_percent     = 90   # Safe allocation threshold
aggressive_allocation_percent = 95   # Aggressive allocation threshold
over_allocation_percent     = 105  # Over-allocation test threshold
```

### Script Parameters
```bash
./scripts/maximum-memory-test.sh [OPTIONS]

OPTIONS:
    -t, --total-ram GB          Total system RAM in GB
    -u, --current-usage MB      Current EVE usage in MB  
    -i, --increment MB          Memory increment for testing
    -c, --max-containers N      Maximum containers for concurrent testing
    -m, --max-single MB         Test single container with specific MB
    -p, --pressure-test         Run memory pressure scenarios
    -o, --oom-test             Run OOM boundary testing
    -a, --all-tests            Run comprehensive test suite
    -h, --help                 Show help
```

## Understanding Results

### Success Indicators
```csv
Status,TestName,Memory,FinalState,Timestamp
SUCCESS,safe-allocation,2044MB,RUNNING,2025-06-23 16:18:00
SUCCESS,moderate-load,1024MB,RUNNING,2025-06-23 16:19:00
```

### Failure Indicators
```csv
MEMORY_REJECTED,over-allocation,2158MB,INSUFFICIENT_MEMORY,2025-06-23 16:20:00
TIMEOUT,extreme-test,2500MB,TIMEOUT,2025-06-23 16:21:00
```

### Key Metrics in Results
- **Deployment Time**: How long container takes to start
- **Memory Allocation**: Actual vs. requested memory
- **System Stability**: EVE responsiveness during testing
- **Error Messages**: Specific failure reasons

## Real-World Example Results

Based on testing a 3GB EVE system:

```
=== EVE Memory Allocation Discovery ===
System: 3.0GB total RAM
Current Usage: 783MB
Available: 2,289MB

Test Results:
✅ 2,044MB: SUCCESS (Safe allocation)
❌ 2,158MB: REJECTED - "Remaining memory bytes 2117533696, app needs 2209792000"
✅ 2,018MB: SUCCESS (Discovered boundary)

Conclusion:
- Maximum container allocation: 2,018MB
- System overhead: 1,054MB (34.3%)
- Available for containers: 2,018MB (65.7%)
```

## Troubleshooting

### Common Issues

**Issue**: `bc: command not found`
```bash
# Solution: Install bc calculator
brew install bc  # macOS
sudo apt-get install bc  # Ubuntu/Debian
```

**Issue**: `eden: command not found`
```bash
# Solution: Ensure Eden is built and in PATH
cd /path/to/eden
make build
export PATH=$PATH:$(pwd)
```

**Issue**: Terraform template errors
```bash
# Solution: Reinitialize Terraform
cd terraform
rm -rf .terraform
terraform init
```

**Issue**: Containers stuck in CREATING_VOLUME
```bash
# Solution: Check EVE storage and restart if needed
./eden clean --current-context
./eden start
```

### Test Validation

Verify your setup works before running tests:
```bash
# 1. Check EVE status
./eden status
# Should show all services running

# 2. Test basic container deployment
./eden pod deploy docker://nginx:alpine --memory=128MB --name=test-basic
./eden pod ps | grep test-basic
# Should show RUNNING status

# 3. Clean up
./eden pod delete test-basic
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: EVE Memory Testing
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  memory-testing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup EVE Testing
        run: |
          brew install terraform bc
          cd memory-testing
          terraform init
          terraform apply -auto-approve
      - name: Run Memory Tests
        run: |
          cd memory-testing
          ./scripts/maximum-memory-test.sh --all-tests
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: memory-test-results
          path: memory-testing/results/
```

## Contributing

### Adding New Test Scenarios
1. Create test function in `scripts/maximum-memory-test.sh`
2. Add configuration parameters to `terraform.tfvars`
3. Update documentation with usage examples
4. Test on multiple EVE configurations

### Reporting Issues
When reporting issues, include:
- EVE system specifications (RAM, CPU, OS)
- Eden version and configuration
- Complete test output and logs
- Expected vs. actual behavior

## Advanced Usage

### Custom Test Scenarios
```bash
# Create custom test for specific use case
cat > custom-test.sh << 'EOF'
#!/bin/bash
source scripts/maximum-memory-test.sh

# Test database workload scenario
test_database_workload() {
    test_single_container 1024 "DATABASE_TEST"
    # Add database-specific validation
}

test_database_workload
EOF
```

### Automated Boundary Detection
```bash
# Find precise memory boundary automatically
./scripts/boundary-finder.sh --auto-detect --precision 5
# Automatically detects system parameters and finds exact limits
```

### Performance Profiling
```bash
# Enable detailed performance monitoring
export EVE_MEMORY_TEST_VERBOSE=1
export EVE_MEMORY_TEST_PROFILE=1
./scripts/maximum-memory-test.sh --all-tests --profile
```

This framework provides a complete solution for validating EVE memory management and can be easily integrated into EVE development workflows, CI/CD pipelines, and production validation processes.