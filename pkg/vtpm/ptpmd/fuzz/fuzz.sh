#!/bin/bash
cp ../src/server.cpp .
patch server.cpp fuzzing.patch
make
printf "\n\n========================================================\n"
printf "Fuzzing started, wait for a crash or press CTRL+C...\n"
./vtpm_server_fuzzer 2>/dev/null
