package downloader

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	// persistRktLocalConfigBase - Base Dir used for LocalConfigDir for
	//  rkt Container images
	persistRktLocalConfigBase = types.PersistDir + "/rktlocal"
)

// getContainerRegistry will extract container registry and form download url
// for rktFetch
func getContainerRegistry(url string) (string, string, error) {
	var urlReg, registryReg, downReg *regexp.Regexp
	var registry, downURL string
	var err error
	urlReg, err = regexp.Compile(`^docker:\/\/(?:.*).io\/(?:.*)`)
	if err != nil {
		return "", "", err
	}
	registryReg, err = regexp.Compile(`(?:.*)(?:\.io)`)
	if err != nil {
		return "", "", err
	}
	downReg, err = regexp.Compile(`(?:.*)(?:\.io)\/`)
	if err != nil {
		return "", "", err
	}
	if urlReg.MatchString(url) {
		registry = strings.TrimPrefix(registryReg.FindString(url), "docker://")
		downURL = downReg.ReplaceAllString(url, "docker://")
		return registry, downURL, nil
	}
	return "", "", fmt.Errorf("Download URL is not formed properly")
}

func rktFetch(url string, localConfigDir string, pullPolicy string, aciDir string) (string, error) {

	// rkt --insecure-options=image fetch <url> --dir=/persist/rkt --full=true
	log.Debugf("rktFetch - url: %s ,  localConfigDir:%s\n",
		url, localConfigDir)
	cmd := "rkt"
	args := []string{
		"--dir=" + types.PersistRktDataDir,
		"--insecure-options=image",
		"fetch",
	}
	if len(localConfigDir) > 0 {
		args = append(args, "--local-config="+localConfigDir)
	}
	if len(pullPolicy) > 0 {
		args = append(args, "--pull-policy="+pullPolicy)
	}
	args = append(args, url)
	args = append(args, "--full=true")

	log.Infof("rktFetch - url: %s ,  localConfigDir:%s, args: %+v\n",
		url, localConfigDir, args)

	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("rkt fetch failed ", err)
		log.Errorln("rkt fetch output ", string(stdoutStderr))
		return "", fmt.Errorf("rkt fetch failed: %s\nImage URL: %s\n",
			string(stdoutStderr), url)
	}
	log.Infof("rktFetch - image fetch successful. stdoutStderr: %s\n",
		stdoutStderr)
	outputStr := string(stdoutStderr)
	log.Debugf("rktFetch - outputStr: %s\n", outputStr)
	outputStrArray := strings.Split(outputStr, "\n")

	log.Debugf("rktFetch - outputStrArray:\n")
	for i, op := range outputStrArray {
		log.Debugf("index:%d, op:%s", i, op)
	}
	log.Debugf("rktFetch - outputStrArray DONE\n")

	// Get ImageID from the oputput. The last line in rkt fetch output
	// with sha12- is the imageID
	imageID := ""
	for i := len(outputStrArray) - 1; i >= 0; i-- {
		imageID = outputStrArray[i]
		if strings.HasPrefix(imageID, "sha512-") {
			break
		}
	}
	log.Infof("rktFetch - imageID: %s\n", imageID)
	if imageID == "" {
		errMsg := "rkt fetch: Can't find imageID.\n Fetch Output: " +
			outputStr
		return "", errors.New(errMsg)
	}

	err = rktImageExport(imageID, aciDir)
	if err != nil {
		return "", err
	}

	// XXX:FIXME - we should run "rkt image ls" and verify image fetch
	// went thru without errors.
	return imageID, nil
}

func rktImageExport(imageHash, aciDir string) error {
	var aciName string
	cmd := "rkt"
	args := []string{
		"--dir=" + types.PersistRktDataDir,
		"--insecure-options=image",
		"image",
		"export",
		imageHash,
	}
	aciName = filepath.Join(aciDir, imageHash)
	aciName = aciName + ".aci"
	args = append(args, aciName)

	log.Infof("rkt image export args: %+v\n", args)

	_, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("rkt image export failed ", err)
		return err
	}
	log.Infof("rktImageExport - image export successful.")
	return nil
}

// createRktLocalDirAndAuthFile
//  Return Values: localConfigDir, AuthFileName, err
func createRktLocalDirAndAuthFile(imageID uuid.UUID,
	dsCtx types.DatastoreContext, registry string) (string, string, error) {

	if len(strings.TrimSpace(dsCtx.APIKey)) == 0 {
		log.Debugf("createRktLocalDirAndAuthFile: empty APIKey. " +
			"Skipping AuthFile")
		return "", "", nil
	}

	// Create Local Directory with name imageSafeName
	// The directory structure should be:
	// <persistRktLocalConfigBase>/<uuid>/auth.d/rktAuth<appName>.json
	localConfigDir := persistRktLocalConfigBase + "/" + imageID.String()
	authDir := localConfigDir + "/auth.d"
	authFileName := authDir + "/docker.json"
	err := os.MkdirAll(authDir, 0755)
	if err != nil {
		log.Errorf("createRktLocalDirAndAuthFile: empty username." +
			" Skipping AuthFile")
		return "", "", fmt.Errorf("Failed create dir %s, err: %+v\n",
			authDir, err)
	}

	rktAuth := types.RktAuthInfo{
		RktKind:    "dockerAuth",
		RktVersion: "v1",
		Registries: []string{registry},
		Credentials: &types.RktCredentials{
			User:     dsCtx.APIKey,
			Password: dsCtx.Password,
		},
	}
	log.Infof("createRktLocalDirAndAuthFile: created Auth file %s\n"+
		"RktKind: %s, RktVersion: %s, Registries: %+v, \n",
		authFileName, rktAuth.RktKind, rktAuth.RktVersion, rktAuth.Registries)

	rktAuthJSON, err := json.MarshalIndent(rktAuth, "", " ")
	if err != nil {
		return "", "", fmt.Errorf("Failed convert rktAuth to json"+
			"err: %+v\n", err)
	}
	err = ioutil.WriteFile(authFileName, rktAuthJSON, 0644)
	if err != nil {
		return "", "", fmt.Errorf("Failed to create Auth file for"+
			"rkt fetch: %+v\n", err)
	}
	return localConfigDir, authFileName, nil
}

func rktFetchContainerImage(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus,
	dsCtx types.DatastoreContext, pullPolicy string, aciDir string) error {
	// update status to DOWNLOAD STARTED
	status.State = types.DOWNLOAD_STARTED
	publishDownloaderStatus(ctx, status)

	imageID := ""
	var authFile, localConfigDir string
	registry, downloadURL, err := getContainerRegistry(dsCtx.DownloadURL)
	if err == nil {
		// Save credentials to Auth file
		log.Infof("rktFetchContainerImage: fetch  <%s>\n", dsCtx.DownloadURL)
		localConfigDir, authFile, err = createRktLocalDirAndAuthFile(
			config.ImageID, dsCtx, registry)
		if err == nil {
			log.Debugf("rktFetchContainerImage: localConfigDir: %s, authFile: %s\n",
				localConfigDir, authFile)
			if len(authFile) == 0 {
				log.Infof("rktFetchContainerImage: no Auth File")
			}
			imageID, err = rktFetch(downloadURL, localConfigDir, pullPolicy, aciDir)
		} else {
			log.Errorf("rktCreateAuthFile Failed. err: %+v", err)
		}
	} else {
		log.Errorf("getContainerRegistry : registry and download url parsing failed. err: %+v", err)
	}

	if err != nil {
		log.Errorf("rktFetchContainerImage: fetch  Failed. url:%s, "+
			"authFile: %s, Err: %+v\n", dsCtx.DownloadURL, authFile, err)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount++
		publishDownloaderStatus(ctx, status)
		return err
	}
	log.Infof("rktFetchContainerImage successful. imageID: <%s>\n",
		imageID)

	// Update globalStatus and status
	unreserveSpace(ctx, status)

	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.
	status.ContainerImageID = imageID
	status.ContainerRktLocalConfigDir = localConfigDir
	status.ContainerRktAuthFileName = authFile
	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	status.Progress = 100 // Just in case
	publishDownloaderStatus(ctx, status)

	return nil
}
