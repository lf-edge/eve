// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 4096

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <size in MB>\n", argv[0]);
        return 1;
    }

    const int pages_to_allocate = atoi(argv[1]) * 1024 * 1024 / PAGE_SIZE;

    char* memory[pages_to_allocate];  // Allocate 1GB

    for (int i = 0; i < pages_to_allocate; i++) {
        memory[i] = (char*)malloc(PAGE_SIZE);
        if (memory[i] == NULL) {
            printf("Failed to allocate memory\n");
            return 1;
        }
        memset(memory[i], 0, PAGE_SIZE);
        printf("Allocated %d KB\n", (i + 1) * 4);
    }
    printf("Press Enter to release memory:");
    getchar();
    for (int i = 0; i < pages_to_allocate; i++) {
        free(memory[i]);
    }
    return 0;
}
