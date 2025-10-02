# EVE Memory Testing Terraform Configuration
terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

# Variables for test configuration
variable "eve_system_ram_gb" {
  description = "Total system RAM in GB"
  type        = number
  default     = 3.0
}

variable "eve_current_usage_mb" {
  description = "Current EVE system usage in MB"
  type        = number
  default     = 800
}

variable "test_duration_minutes" {
  description = "Duration of each test in minutes"
  type        = number
  default     = 5
}

variable "max_test_containers" {
  description = "Maximum number of containers for concurrent testing"
  type        = number
  default     = 5
}

variable "safe_allocation_percent" {
  description = "Safe allocation percentage of available memory"
  type        = number
  default     = 90
}

variable "aggressive_allocation_percent" {
  description = "Aggressive allocation percentage of available memory"
  type        = number
  default     = 95
}

# Calculate memory parameters
locals {
  total_ram_mb = var.eve_system_ram_gb * 1024
  available_ram_mb = local.total_ram_mb - var.eve_current_usage_mb
  safe_max_mb = floor(local.available_ram_mb * var.safe_allocation_percent / 100)
  aggressive_max_mb = floor(local.available_ram_mb * var.aggressive_allocation_percent / 100)
  
  # Test scenarios for automated testing
  test_scenarios = [
    {
      name        = "light-load"
      ram_mb      = 128
      cpu_cores   = 1
      description = "Light memory allocation test"
    },
    {
      name        = "moderate-load"
      ram_mb      = 256
      cpu_cores   = 1
      description = "Moderate memory allocation test"
    },
    {
      name        = "heavy-load"
      ram_mb      = 512
      cpu_cores   = 2
      description = "Heavy memory allocation test"
    },
    {
      name        = "safe-max"
      ram_mb      = local.safe_max_mb
      cpu_cores   = 2
      description = "Safe maximum allocation test"
    }
  ]
}

# Generate test runner script
resource "local_file" "test_runner" {
  filename = "${path.module}/../scripts/automated-test-runner.sh"
  file_permission = "0755"
  content = templatefile("${path.module}/templates/test-runner.tpl", {
    test_scenarios = local.test_scenarios
    duration_minutes = var.test_duration_minutes
    total_ram_gb = var.eve_system_ram_gb
    current_usage_mb = var.eve_current_usage_mb
  })
}

# Generate configuration file
resource "local_file" "test_config" {
  filename = "${path.module}/../config/test-config.env"
  content = templatefile("${path.module}/templates/config.tpl", {
    total_ram_mb = local.total_ram_mb
    available_ram_mb = local.available_ram_mb
    safe_max_mb = local.safe_max_mb
    aggressive_max_mb = local.aggressive_max_mb
    test_duration = var.test_duration_minutes
    max_containers = var.max_test_containers
  })
}

# Output test configuration
output "test_configuration" {
  value = {
    total_system_ram_gb = var.eve_system_ram_gb
    current_usage_mb = var.eve_current_usage_mb
    available_ram_mb = local.available_ram_mb
    safe_max_mb = local.safe_max_mb
    aggressive_max_mb = local.aggressive_max_mb
    test_scenarios = local.test_scenarios
  }
}
