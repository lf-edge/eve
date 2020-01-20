package domainmgr

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	docker2aci "github.com/appc/docker2aci/lib"
	"github.com/appc/docker2aci/lib/common"
	acilog "github.com/appc/docker2aci/pkg/log"
	legacytarball "github.com/google/go-containerregistry/pkg/legacy/tarball"
	"github.com/google/go-containerregistry/pkg/name"
	v1tarball "github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	// rktDockerManifestHashLabel label name for the annotation that stores the docker hash
	rktDockerManifestHashLabel = "appc.io/docker/manifesthash"
)

// KeyValue a key-value pair with labels in rkt manifest
type KeyValue struct {
	Name  string
	Value string
}

// RktManifest represents a rkt manifest
type RktManifest struct {
	ACKind        string       `json:"acKind"`
	ACVersion     string       `json:"acVersion"`
	Name          string       `json:"name"`
	Labels        []Label      `json:"labels,omitempty"`
	App           App          `json:"app,omitempty"`
	Dependencies  []Dependency `json:"dependencies,omitempty"`
	PathWhitelist []string     `json:"pathWhitelist,omitempty"`
	Annotations   []Annotation `json:"annotations,omitempty"`
}

type Annotation struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	ImageName string  `json:"imageName"`
	ImageID   string  `json:"imageID,omitempty"`
	Labels    []Label `json:"labels,omitempty"`
	Size      uint    `json:"size,omitempty"`
}

type EventHandler struct {
	Name string   `json:"name"`
	Exec []string `json:"exec"`
}

type EnvironmentVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MountPoint struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type Port struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	Port            uint   `json:"port"`
	Count           uint   `json:"count"`
	SocketActivated bool   `json:"socketActivated"`
}

type IsolatorValue struct {
	Request string `json:"request"`
	Limit   string `json:"limit"`
}

type Isolator struct {
	Name  string        `json:"name"`
	Value IsolatorValue `json:"value"`
}

type App struct {
	Exec              []string              `json:"exec"`
	EventHandlers     []EventHandler        `json:"eventHandlers,omitempty"`
	User              string                `json:"user"`
	Group             string                `json:"group"`
	SupplementaryGIDs []int                 `json:"supplementaryGIDs,omitempty"`
	WorkingDirectory  string                `json:"workingDirectory,omitempty"`
	Environment       []EnvironmentVariable `json:"environment,omitempty"`
	MountPoints       []MountPoint          `json:"mountPoints,omitempty"`
	Ports             []Port                `json:"ports,omitempty"`
	Isolators         []Isolator            `json:"isolators,omitempty"`
	UserAnnotations   map[string]string     `json:"userAnnotations,omitempty"`
	UserLabels        map[string]string     `json:"userLabels,omitempty"`
}

// rktConvertTarToAci convert an OCI image tarfile into an ACI bundle
// with thanks to https://github.com/appc/docker2aci
// from is the file to convert from; to is the path where to place the aci file
func rktConvertTarToAci(from, to string) ([]string, error) {
	var convertTag string
	legacyTmpDir, err := ioutil.TempDir("", "v1ToLegacyTarContainer")
	if err != nil {
		return nil, fmt.Errorf("error creating temporary directory for v1 to legacy tar conversion")
	}
	defer os.RemoveAll(legacyTmpDir)
	legacyPath := path.Join(legacyTmpDir, "legacytar")
	tmpDir, err := ioutil.TempDir("", "docker2aci")
	if err != nil {
		return nil, fmt.Errorf("error creating temporary directory for aci conversion")
	}
	// first convert from v1 to legacy
	img, err := v1tarball.ImageFromPath(from, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to get image from v1 tarball %s input: %v", from, err)
	}
	// get the tag
	if convertTag == "" {
		tags, err := getTagsFromV1Tar(from)
		if err != nil {
			return nil, fmt.Errorf("unable to read tags from v1 tar at %s: %v", from, err)
		}
		if len(tags) < 1 {
			return nil, fmt.Errorf("no tags in tar file at %s and none provided on command line", from)
		}
		convertTag = tags[0]
	}
	// taken straight from pkg/crane.Save, but they don't have the options there
	ref, err := name.ParseReference(convertTag)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %v", convertTag, err)
	}
	tag, ok := ref.(name.Tag)
	if !ok {
		return nil, fmt.Errorf("ref wasn't a tag or digest")
	}
	var w *os.File
	w, err = os.Create(legacyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open %s to write legacy tar file: %v", legacyPath, err)
	}
	defer w.Close()
	err = legacytarball.Write(tag, img, w)
	if err != nil {
		return nil, fmt.Errorf("unable to write legacy tar file %s: %v", legacyPath, err)
	}
	w.Close()

	cfg := docker2aci.CommonConfig{
		Squash:      true,
		OutputDir:   to,
		TmpDir:      tmpDir,
		Compression: common.GzipCompression,
		Debug:       acilog.NewNopLogger(),
		Info:        acilog.NewStdLogger(os.Stderr),
	}

	fileConfig := docker2aci.FileConfig{
		CommonConfig: cfg,
		DockerURL:    "",
	}
	return docker2aci.ConvertSavedFile(legacyPath, fileConfig)
}

// rktAddEnvVariableManifest extracts the the given ACI, adds the passed environment variable to it
// and overwrite the existing ACI file with Actool
func rktAddEnvVariableManifest(aciFilepaths []string, envVars []EnvironmentVariable) ([]string, error) {

	//Below If statement is only to test if env var is set properly.
	//TODO: Once passing env var from UI is implemented, then this If condition will be removed.
	if envVars == nil {
		envVars = append(envVars, EnvironmentVariable{
			Name:  "FOO",
			Value: "bar",
		})
	}

	tarCmd := "tar"
	tarBaseArg := "xvf"
	actoolCmd := "actool"
	actoolBaseArg := []string{"build", "--overwrite"}

	//Adding passed env variables to all the ACI file in the list
	for _, aciFilePath := range aciFilepaths {
		//Creating a temp dir where ACI file will be extracted
		tmpDirExtract, err := ioutil.TempDir("", "aciFileExtract")
		if err != nil {
			return []string{}, fmt.Errorf("error creating temporary directory for aci caching")
		}
		tarArgs := []string{
			tarBaseArg,
			aciFilePath,
			"-C",
			tmpDirExtract,
		}
		log.Infof("Calling command %s %v\n", tarCmd, tarArgs)
		cmdLine := exec.Command(tarCmd, tarArgs...)
		stdoutStderr, err := cmdLine.CombinedOutput()
		if err != nil {
			outerr := string(stdoutStderr)
			log.Errorf("ACI file %s extract failed: %v", aciFilePath, err)
			return []string{}, fmt.Errorf("ACI file %s extract failed: %v", aciFilePath, outerr)
		}

		//Reading the manifest of extracted ACI file and Unmarshalling it into 'RktManifest' struct
		manifestFile, err := os.Open(tmpDirExtract + "/manifest")
		manifestFileBytes, _ := ioutil.ReadAll(manifestFile)
		var manifest RktManifest
		err = json.Unmarshal(manifestFileBytes, &manifest)

		//Add environment variables
		manifest.App.Environment = append(manifest.App.Environment, envVars...)
		file, err := json.MarshalIndent(manifest, "", " ")
		if err != nil {
			log.Errorf("ACI file %s write failed: %v", aciFilePath, err)
			return []string{}, fmt.Errorf("ACI file %s write failed: %v", aciFilePath, err)
		}

		//Updating extracted ACI's manifest
		err = ioutil.WriteFile(tmpDirExtract+"/manifest", file, 0644)
		if err != nil {
			log.Errorf("ACI file %s write failed: %v", aciFilePath, err)
			return []string{}, fmt.Errorf("ACI file %s write failed: %v", aciFilePath, err)
		}

		//Rebuilding ACI file with updated manifest. This is overwrite the existing ACI file.
		actoolArgs := append(actoolBaseArg, tmpDirExtract, aciFilePath)
		log.Infof("Calling command %s %v\n", actoolCmd, actoolArgs)
		cmdLine = exec.Command(actoolCmd, actoolArgs...)
		stdoutStderr, err = cmdLine.CombinedOutput()
		if err != nil {
			outerr := string(stdoutStderr)
			log.Errorf("ACI file %s re-create failed: %v", aciFilePath, outerr)
			return []string{}, fmt.Errorf("ACI file %s re-create  failed: %v", aciFilePath, outerr)
		}

		os.RemoveAll(tmpDirExtract)
		manifestFile.Close()
	}
	return aciFilepaths, nil
}

// ociToRktImageHash given an OCI tar file, get the rkt hash for it.
// Searches in the rkt image cache. If it finds a matching image by docker
// manifest hash, it returns the rkt hash for the image. If it does not find a
// matching image by hash, it takes the OCI tar file, converts it to a `.aci`
// file in a temporary directory, loads it into the rkt cache, and returns that.
func ociToRktImageHash(ociFilename string) (string, error) {
	// first get the list of hashes available in rkt already
	hashes, err := rktGetHashes()
	if err != nil {
		return "", fmt.Errorf("error getting rkt hashes: %v", err)
	}
	// next get the hash for the given file
	// we are assuming that there is only one repo tag in the "repositories" file.
	// this will not be true long-run, but this all goes away when rkt does.
	dockerHash, err := ociGetHash(ociFilename)
	if err != nil {
		return "", fmt.Errorf("error getting hash of repository for OCI file %s: %v", ociFilename, err)
	}
	// if we already have it, just return it
	if rktHash, ok := hashes[dockerHash]; ok {
		log.Infof("rkt hash %s for docker hash %s already exists in rkt cache", rktHash, dockerHash)
		return rktHash, nil
	}

	// if we made it here, we didn't find it, so convert the file to an aci and load it
	tmpDir, err := ioutil.TempDir("", "acifile")
	if err != nil {
		return "", fmt.Errorf("error creating temporary directory for aci caching")
	}
	defer os.RemoveAll(tmpDir)
	aciFiles, err := rktConvertTarToAci(ociFilename, tmpDir)
	if err != nil {
		return "", fmt.Errorf("unable to convert %s to aci: %v", ociFilename, err)
	}
	if len(aciFiles) < 1 {
		return "", fmt.Errorf("convert %s to aci did not return aci file", ociFilename)
	}

	updatedAciFiles, err := rktAddEnvVariableManifest(aciFiles, nil)
	if err != nil {
		return "", fmt.Errorf("unable to add enviornment variable to aci: %v. Error: %v", err, aciFiles[0])
	}
	if len(aciFiles) < 1 {
		return "", fmt.Errorf("add enviornment variable to aci: %v, did not return aci file", aciFiles[0])
	}

	// import the aciFile
	rktHash, err := rktImportAciFile(updatedAciFiles[0])
	if err != nil {
		return rktHash, fmt.Errorf("unable to import aci file %s from tarfile %s to rkt: %v", aciFiles[0], ociFilename, err)
	}
	log.Infof("found rkt hash %s for docker hash %s", rktHash, dockerHash)
	return rktHash, nil
}

// rktGetHashes get a map of docker manifest hashes to rkt hashes
func rktGetHashes() (map[string]string, error) {
	log.Info("rktGetHashes")

	m := map[string]string{}

	cmd := "rkt"
	baseArgs := []string{
		"--dir=" + types.PersistRktDataDir,
		"--insecure-options=image",
	}
	args := append(baseArgs,
		"image",
		"list",
		"--fields=id",
		"--no-legend",
	)
	log.Infof("Calling command %s %v\n", cmd, args)
	cmdLine := exec.Command(cmd, args...)
	stdoutStderr, err := cmdLine.CombinedOutput()
	if err != nil {
		log.Errorln("rkt image list failed ", err)
		log.Errorln("rkt image list output ", string(stdoutStderr))
		return m, fmt.Errorf("rkt image list failed: %s\n", string(stdoutStderr))
	}
	// get all of the rkt image hashes
	rktHashes := strings.Fields(string(stdoutStderr))
	// now go through each one and get its docker hash
	for _, rh := range rktHashes {
		args = append(baseArgs,
			"image",
			"cat-manifest",
			rh,
		)
		cmdLine = exec.Command(cmd, args...)
		stdoutStderr, err = cmdLine.CombinedOutput()
		if err != nil {
			log.Errorf("rkt image cat-manifest %s failed: %v", rh, err)
			log.Errorf("rkt image cat-manifest %s output: %v", rh, string(stdoutStderr))
			return m, fmt.Errorf("rkt image cat-manifest %s failed: %s", rh, string(stdoutStderr))
		}
		// process the json to get the exact item we need
		var manifest RktManifest
		err = json.Unmarshal(stdoutStderr, &manifest)
		if err != nil {
			return m, fmt.Errorf("error parsing rkt manifest for %s: %v", rh, err)
		}
		// go through the annotations to find the hash for the correct label
		for _, a := range manifest.Annotations {
			if a.Name == rktDockerManifestHashLabel {
				m[a.Value] = rh
				break
			}
		}
	}

	log.Infof("rkt hashes load complete; found %d images with docker hashes", len(m))
	log.Debugf("rkt hashes: %+v", m)
	return m, nil
}

// ociGetHash extract the hash from an OCI tar file
func ociGetHash(ociFilename string) (string, error) {
	// docker2aci already implemented this... and then put it in an internal
	// package that we cannot import. That's a pity. But since this is
	// going to be short-lived, we will live with it. In any case, it all is
	// Apache 2.0 from
	// https://github.com/appc/docker2aci/blob/248258bd708afc51c1aa0f9e8b826c50d1ce66a8/lib/internal/backend/file/file.go
	log.Infof("ociGetHash: from %s", ociFilename)

	var (
		hash, appName string
		repob         []byte
	)

	// open our tar file for reading
	f, err := os.Open(ociFilename)
	if err != nil {
		return hash, fmt.Errorf("error opening file: %v", err)
	}
	defer f.Close()

	type tags map[string]string
	type apps map[string]tags

	// read the tarball until we find the "repositories" file
	tr := tar.NewReader(f)

tarloop:
	for {
		header, err := tr.Next()

		switch {
		// if no more files are found
		case err == io.EOF:
			break tarloop
		case err != nil:
			return hash, fmt.Errorf("error reading tar entry: %v", err)
		case header == nil:
			continue
		// we only care about a regular file named "repositories"
		case header.Typeflag == tar.TypeReg:
			clean := filepath.Clean(header.Name)
			// we only are looking at the repositories file
			if clean != "repositories" {
				continue
			}
			repob, err = ioutil.ReadAll(tr)
			if err != nil {
				return hash, fmt.Errorf("error reading repositories file: %v", err)
			}
			// we already saved the bytes, so break; we are done with the file
			break tarloop
		}
	}

	// load the json content of the "repositories" file into an apps struct
	var unparsedRepositories apps
	if err := json.Unmarshal(repob, &unparsedRepositories); err != nil {
		return hash, fmt.Errorf("error unmarshaling repositories file")
	}

	repositories := make(apps, 0)
	// Normalize repository keys since the image potentially passed in is
	// normalized - this is exported by docker2aci
	for key, val := range unparsedRepositories {
		parsed, err := common.ParseDockerURL(key)
		if err != nil {
			return hash, fmt.Errorf("error parsing key %q in repositories: %v", key, err)
		}
		repositories[parsed.ImageName] = val
	}

	n := len(repositories)
	switch {
	case n == 1:
		for key := range repositories {
			appName = key
		}
	case n > 1:
		var appNames []string
		for key := range repositories {
			appNames = append(appNames, key)
		}
		return hash, fmt.Errorf("more than one repository found in tar file: %v", appNames)
	default:
		return hash, fmt.Errorf("no images found")
	}

	app, ok := repositories[appName]
	if !ok {
		return hash, fmt.Errorf("app %q not found", appName)
	}

	n = len(app)
	switch {
	case n == 1:
		for _, value := range app {
			hash = value
		}
	case n > 1:
		var tagNames []string
		for key := range app {
			tagNames = append(tagNames, key)
		}
		return hash, fmt.Errorf("more than one tag found for %s in tar file: %v", appName, tagNames)
	default:
		return hash, fmt.Errorf("no tags found for %s", appName)
	}

	if hash == "" {
		return hash, fmt.Errorf("Could not find hash")
	}
	log.Infof("ociGetHash: got hash %s", hash)
	return hash, nil
}

// rktImportAciFile import a local aci file into the rkt cache. returns the
// rkt hash and any errors.
func rktImportAciFile(aciFilename string) (string, error) {
	log.Info("rktGetHashes")

	cmd := "rkt"
	baseArgs := []string{
		"--dir=" + types.PersistRktDataDir,
		"--insecure-options=image",
	}
	args := append(baseArgs,
		"fetch",
		aciFilename,
	)
	log.Infof("Calling command %s %v\n", cmd, args)
	cmdLine := exec.Command(cmd, args...)
	stdoutStderr, err := cmdLine.CombinedOutput()
	outerr := string(stdoutStderr)
	if err != nil {
		log.Errorf("rkt fetch %s failed: %v", aciFilename, err)
		log.Errorf("rkt fetch %s output: %s", aciFilename, outerr)
		return "", fmt.Errorf("rkt fetch %s failed: %s\n", aciFilename, outerr)
	}
	// do not forget to remove the trailing CRLF
	return strings.Trim(outerr, "\n"), nil
}

func getTagsFromV1Tar(tarfile string) ([]string, error) {
	// open the tar file for reading
	var (
		f     *os.File
		err   error
		repob []byte
	)
	type tags map[string]string
	type apps map[string]tags

	// open the existing file
	if f, err = os.Open(tarfile); err != nil {
		return nil, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	// cycle through until we find the "repositories" file
tarloop:
	for {
		header, err := tr.Next()

		switch {
		// if no more files are found
		case err == io.EOF:
			break tarloop
		case err != nil:
			return nil, fmt.Errorf("error reading tar entry: %v", err)
		case header == nil:
			continue
		// we only care about a regular file named "repositories"
		case header.Typeflag == tar.TypeReg:
			clean := filepath.Clean(header.Name)
			// we only are looking at the repositories file
			if clean != "repositories" {
				continue
			}
			repob, err = ioutil.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("error reading repositories file: %v", err)
			}
			// we already saved the bytes, so break; we are done with the file
			break tarloop
		}
	}

	// did we load anything?
	if len(repob) == 0 {
		return nil, nil
	}
	// load the json content of the "repositories" file into an apps struct
	var repos apps
	if err := json.Unmarshal(repob, &repos); err != nil {
		return nil, fmt.Errorf("error unmarshaling repositories file")
	}

	tagList := make([]string, 0)
	for reponame, v := range repos {
		for repotag := range v {
			tagList = append(tagList, fmt.Sprintf("%s:%s", reponame, repotag))
		}
	}
	return tagList, nil
}
