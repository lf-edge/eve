# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

import pandas as pd
import matplotlib.pyplot as plt

def plot_fssagg_average_time(df, filename):
    # Plot Average Secure Time and Average Non-Secure Time for each run
    plt.figure(figsize=(10, 6))
    plt.plot(df['Test Run'], df['Average Secure Time (us)'], label='Average Secure Time (us)', marker='o')
    plt.plot(df['Test Run'], df['Average Non-Secure Time (us)'], label='Average Non-Secure Time (us)', marker='o')
    plt.xlabel('Test Run')
    plt.ylabel('Time (us)')
    plt.title('Average Secure and Non-Secure Time for Each Run')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def plot_fssagg_average_cost(df, filename):
    # Create a figure for Performance Overhead and Performance Cost
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Plot Performance Overhead on the left y-axis
    ax1.plot(df['Test Run'], df['Performance Overhead (%)'], label='Performance Overhead (%)', marker='o', color='red')
    ax1.set_xlabel('Test Run')
    ax1.set_ylabel('Performance Overhead (%)', color='red')
    ax1.tick_params(axis='y', labelcolor='red')
    ax1.grid(True)

    # Create a second y-axis for Performance Cost on the right
    ax2 = ax1.twinx()
    ax2.plot(df['Test Run'], df['Performance Cost (us)'], label='Performance Cost (us)', marker='x', color='blue')
    ax2.set_ylabel('Performance Cost (us)', color='blue')
    ax2.tick_params(axis='y', labelcolor='blue')

    # Title and legend
    plt.title('Performance Overhead and Performance Cost for Each Run')
    fig.tight_layout()  # Adjust the layout to avoid overlap
    ax1.legend(loc='upper left')
    ax2.legend(loc='upper right')

    # Save the plot as PNG
    plt.savefig(filename)  
    plt.close()

file_path = 'fssaggver_cached_keys_10000_timing_results.csv'
df = pd.read_csv(file_path)
plot_fssagg_average_time(df, 'fssaggver_cached_keys_10000_average_secure_non_secure_time.png')
plot_fssagg_average_cost(df, 'fssaggver_cached_keys_10000_overhead_and_cost.png')

file_path = 'fssaggver_timing_results.csv'
df = pd.read_csv(file_path)
plot_fssagg_average_time(df, 'fssaggver_average_secure_non_secure_time.png')
plot_fssagg_average_cost(df, 'fssaggver_overhead_and_cost.png')


file_path = 'fssaggsig_timing_results.csv'
df = pd.read_csv(file_path)
plot_fssagg_average_time(df, 'fssaggsig_average_secure_non_secure_time.png')
plot_fssagg_average_cost(df, 'fssaggsig_overhead_and_cost.png')
