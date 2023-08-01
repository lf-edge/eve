# How to fuzz?

Compare to other tests, Fuzzers should run for a longer time (for example 36h+) to reach a acceptable code coverage (CC). Because of this we build the fuzzer manually and run it separately.

Please note that with new changes coming to VTPM, the fuzzer patch must be updated to include the new changes and the updated version should run to get at least 95%+ code coverage (high CC is not a indicator of no bugs, but it's reasonable approximation).

## Running the Fuzzer

This is a bit crude, but gets the job done. The `fuzzing.patch` creates a stripped-down version of VTPM server that consumes input from the LibFuzzer in-memory buffer rather than the network. Here are simple steps to get started:

* Install clang using `install-clang.sh`
* Run `fuzz.sh`

To see the code coverage data, first need to parse the binary data using `llvm-cov`, for example to see the uncovered lines from server, execute the following command :

```bash
llvm-cov gcov -s "server.cpp" -r server.gcda && cat server.cpp.gcov | grep "#####"
```
