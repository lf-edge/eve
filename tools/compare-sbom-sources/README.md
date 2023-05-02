# compare-sbom-sources

A small utility to compare the packages in an SBoM with the packages in a
sources manifest.

* The SBoM is expected to be in SPDX json format.
* The sources manifest is expected to be in CSV format.

The sources manifest CSV format should contain the following fields:

```csv
packageType,packageNameWithVersion,commit,path
```

Where:

* `packageType` is one of the supported package types, currently: `golang`, `alpine`
* `packageNameWithVersion` is the package name with version, separated by the natural format for that package type:
  * alpine: `name-version`, e.g. `agetty-2.38-r1`
  * golang: `name@version`, e.g. `github.com/eriknordmark/ipinfo@v0.0.0-20190220084921-7ee0839158f9`
* `commit` is the commit for the package in its source repository, if known
* `path` is the path to the package in a packaged sources file, like a zip or tar file

The `commit` and `path` fields are ignored for this comparison.

## Usage

```bash
compare <csv_file> <spdx_file>
```

You can limit the types to compare by using the `--types` flag:

```bash
# will only report on and compare alpine packages
compare --types alpine <csv_file> <spdx_file>
```

## Output

The output has the following format. It currently is not machine parsable,
although that can be added upon request.

There are 3 sections:

* Packages in CSV file but not in SPDX file: a list of packages found in the CSV manifest but not the SPDX, one package per line.
* Packages in SPDX file but not in CSV file: a list of packages found in the SPDX manifest but not the CSV, one package per line.
* Summary statistics.

The summary statistics list the number of packages found in each file, the number
overlapping in both files, and the number in one but not the other.

For example, a successful, fully-reconciled alpine comparison shows:

```text
Packages in CSV file but not in SPDX file:

Packages in SPDX file but not in CSV file:

For types: [alpine]
Total in SPDX file: 228
Total in CSV file: 228
In SPDX but not in CSV: 0
In CSV but not in SPDX: 0
In both: 228
```
