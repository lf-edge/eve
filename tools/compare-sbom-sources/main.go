// Copyright(c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var defaultTypes = []string{"golang", "alpine"}

type singlePackage struct {
	nameVersion string
	ptype       string
}

func (s singlePackage) String() string {
	return fmt.Sprintf("%s:%s", s.ptype, s.nameVersion)
}

// ExternalRef represents the external reference information in the SPDX document, multiple per package.
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXPackage represents the package information in the SPDX document, multiple per SPDX document
type SPDXPackage struct {
	Name         string        `json:"name"`
	SPDXID       string        `json:"SPDXID"`
	VersionInfo  string        `json:"versionInfo"`
	ExternalRefs []ExternalRef `json:"externalRefs"`
}

// SPDXDocument represents an SPDX document
type SPDXDocument struct {
	Packages []SPDXPackage `json:"packages"`
}

func parseJSONFile(r io.Reader) (map[string]*singlePackage, error) {
	jsonPackages := make(map[string]*singlePackage)

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error reading JSON file: %v", err)
	}

	// Decode the JSON content into the SPDXDocument struct
	var spdxDoc SPDXDocument
	err = json.Unmarshal(data, &spdxDoc)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	// Iterate through the packages and store the package information in the map
	for _, pkg := range spdxDoc.Packages {
		purl := ""
		for _, extRef := range pkg.ExternalRefs {
			if extRef.ReferenceType == "purl" {
				purl = extRef.ReferenceLocator
				break
			}
		}
		if purl == "" {
			continue
		}

		pkgPrefix := "pkg:"
		packageTypeIndex := strings.Index(purl, pkgPrefix) + len(pkgPrefix)
		packageTypeAndRest := purl[packageTypeIndex:]
		packageTypeAndRestParts := strings.SplitN(packageTypeAndRest, "/", 2)
		if len(packageTypeAndRestParts) != 2 {
			continue
		}

		packageType := packageTypeAndRestParts[0]
		packageNameAndVersion := packageTypeAndRestParts[1]
		var resolved *singlePackage
		switch packageType {
		case "golang":
			packageNameAndVersion = strings.SplitN(packageNameAndVersion, "?", 2)[0]
			resolved = &singlePackage{
				nameVersion: packageNameAndVersion,
				ptype:       packageType,
			}
		case "apk":
			lastSlashIndex := strings.LastIndex(packageNameAndVersion, "/")
			if lastSlashIndex == -1 {
				continue
			}
			packageNameAndVersion = packageNameAndVersion[lastSlashIndex+1:]
			packageNameAndVersion = strings.SplitN(packageNameAndVersion, "?", 2)[0]
			parts := strings.SplitN(packageNameAndVersion, "@", 2)
			name, version := parts[0], ""
			if len(parts) == 2 {
				version = parts[1]
			}

			resolved = &singlePackage{
				nameVersion: fmt.Sprintf("%s-%s", name, version),
				ptype:       "alpine",
			}
		default:
			continue
		}
		jsonPackages[resolved.String()] = resolved
	}

	return jsonPackages, nil
}

func parseCSVFile(r io.Reader) (map[string]*singlePackage, error) {
	csvPackages := make(map[string]*singlePackage)

	reader := csv.NewReader(r)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV file: %v", err)
		}

		// Check the number of fields in the record
		if len(record) != 4 {
			return nil, fmt.Errorf("invalid number of fields in CSV record: %v", record)
		}

		packageType := record[0]
		packageNameWithVersion := record[1]

		var resolved *singlePackage
		switch packageType {
		case "golang":
			resolved = &singlePackage{
				nameVersion: packageNameWithVersion,
				ptype:       packageType,
			}
		case "alpine":
			resolved = &singlePackage{
				nameVersion: packageNameWithVersion,
				ptype:       packageType,
			}
		default:
			continue
		}

		csvPackages[resolved.String()] = resolved
	}

	return csvPackages, nil
}

func compareMaps(csvPackages, jsonPackages map[string]*singlePackage) (csvNotInJSON []*singlePackage, jsonNotInCSV []*singlePackage) {
	for key, val := range csvPackages {
		if _, ok := jsonPackages[key]; !ok {
			csvNotInJSON = append(csvNotInJSON, val)
		}
	}

	for key, val := range jsonPackages {
		if _, ok := csvPackages[key]; !ok {
			jsonNotInCSV = append(jsonNotInCSV, val)
		}
	}

	return csvNotInJSON, jsonNotInCSV
}

func getFileReader(filename string) (io.Reader, error) {
	parts := strings.Split(filename, ":")
	if len(parts) == 1 {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("error opening file: %v", err)
		}
		return file, nil
	}

	archiveFile := parts[0]
	targetFile := parts[1]

	if strings.HasSuffix(archiveFile, ".tgz") || strings.HasSuffix(archiveFile, ".tar.gz") {
		file, err := os.Open(archiveFile)
		if err != nil {
			return nil, fmt.Errorf("error opening .tar.gz file: %v", err)
		}
		defer file.Close()

		gzr, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer gzr.Close()

		tr := tar.NewReader(gzr)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("error reading .tar.gz file: %v", err)
			}
			if hdr.Name == targetFile {
				return tr, nil
			}
		}
	} else if strings.HasSuffix(archiveFile, ".tar") {
		file, err := os.Open(archiveFile)
		if err != nil {
			return nil, fmt.Errorf("error opening .tar file: %v", err)
		}
		defer file.Close()

		tr := tar.NewReader(file)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("error reading .tar file: %v", err)
			}
			if hdr.Name == targetFile {
				return tr, nil
			}
		}
	}

	return nil, fmt.Errorf("file not found in archive")
}

func main() {
	var types []string
	var rootCmd = &cobra.Command{
		Use:   "compare <csv_file> <json_file>",
		Short: "Compare CSV and SPDX JSON files",
		Long: `Compares the specified CSV and SPDX JSON files and reports any packages not present in both files.

Arguments:
	csv_file       Path to the CSV file
	spdx_json_file Path to the SPDX JSON file
			`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			csvFile := args[0]
			jsonFile := args[1]
			// Create a map of the specified types
			typesMap := make(map[string]bool)
			for _, t := range types {
				typesMap[t] = true
			}

			csvReader, err := getFileReader(csvFile)
			if err != nil {
				log.Fatalf("Error getting CSV file reader: %v", err)
			}

			jsonReader, err := getFileReader(jsonFile)
			if err != nil {
				log.Fatalf("Error getting JSON file reader: %v", err)
			}

			csvPackages, err := parseCSVFile(csvReader)
			if err != nil {
				log.Fatalf("Error parsing CSV file: %v", err)
			}

			jsonPackages, err := parseJSONFile(jsonReader)
			if err != nil {
				log.Fatalf("Error parsing JSON file: %v", err)
			}
			typeRestrictedCSVPackages, typeRestrictedJSONPackages := make(map[string]*singlePackage), make(map[string]*singlePackage)
			for _, pkg := range csvPackages {
				if _, ok := typesMap[pkg.ptype]; ok {
					typeRestrictedCSVPackages[pkg.String()] = pkg
				}
			}
			for _, pkg := range jsonPackages {
				if _, ok := typesMap[pkg.ptype]; ok {
					typeRestrictedJSONPackages[pkg.String()] = pkg
				}
			}

			csvNotInJSON, jsonNotInCSV := compareMaps(typeRestrictedCSVPackages, typeRestrictedJSONPackages)

			fmt.Println("Packages in CSV file but not in SPDX file:")
			for _, pkg := range csvNotInJSON {
				fmt.Println(pkg)
			}

			fmt.Println("\nPackages in SPDX file but not in CSV file:")
			for _, pkg := range jsonNotInCSV {
				fmt.Println(pkg)
			}

			fmt.Println()
			fmt.Printf("For types: %v\n", types)
			fmt.Printf("Total in SPDX file: %d\n", len(typeRestrictedJSONPackages))
			fmt.Printf("Total in CSV file: %d\n", len(typeRestrictedCSVPackages))
			fmt.Printf("In SPDX but not in CSV: %d\n", len(jsonNotInCSV))
			fmt.Printf("In CSV but not in SPDX: %d\n", len(csvNotInJSON))
			fmt.Printf("In both: %d\n", len(typeRestrictedJSONPackages)-len(jsonNotInCSV))
		},
	}
	rootCmd.Flags().StringSliceVar(&types, "types", defaultTypes, "Comma-separated list of types to filter")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
