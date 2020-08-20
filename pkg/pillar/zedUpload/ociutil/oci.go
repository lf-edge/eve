package ociutil

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	log "github.com/sirupsen/logrus"
)

const (
	digestTag = "digest-without-tag"
)

// UpdateStats single status update for an OCI transfer
type UpdateStats struct {
	Size  int64    // complete size to upload/download
	Asize int64    // current size uploaded/downloaded
	Tags  []string //list of tags for given image
	Error error
}

// NotifChan channel for sending status updates
type NotifChan chan UpdateStats

// Tags return all known tags for a given repository on a given registry.
// Optionally, can use authentication of username and apiKey as provided, else defaults
// to the local user config. Also can use a given http client, else uses the default.
// Returns a slice of tags of the repo passed to it, and error, if any.
func Tags(registry, repository, username, apiKey string, client *http.Client, prgchan NotifChan) ([]string, error) {
	var (
		tags  []string
		err   error
		image = fmt.Sprintf("%s/%s", registry, repository)
	)

	repo, err := name.NewRepository(image)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %v", image, err)
	}

	opts := options(username, apiKey, client)

	tags, err = remote.List(repo, opts...)
	if err != nil {
		return nil, fmt.Errorf("error listing tags: %v", err)
	}
	return tags, nil
}

// Manifest retrieves the manifest for a repo from a registry and returns it.
// Optionally, can use authentication of username and apiKey as provided, else defaults
// to the local user config. Also can use a given http client, else uses the default.
// Returns the manifest of the repo passed to it, the manifest of the resolved image,
// which either is the same as the repo manifest if an image, or the repo resolved
// from a manifest index, the size of the entire image, and error, if any.
func Manifest(registry, repo, username, apiKey string, client *http.Client, prgchan NotifChan) ([]byte, []byte, int64, error) {
	var (
		manifestDirect, manifestResolved []byte
		size                             int64
		err                              error
		image                            = fmt.Sprintf("%s/%s", registry, repo)
	)

	opts := options(username, apiKey, client)

	_, _, _, manifestDirect, manifestResolved, size, err = manifestsDescImg(image, opts)
	return manifestDirect, manifestResolved, size, err
}

// PullBlob downloads a blob from a registry and save it as a file as-is.
func PullBlob(registry, repo, hash, localFile, username, apiKey string, maxsize int64, client *http.Client, prgchan NotifChan) (int64, string, error) {
	log.Infof("PullBlob(%s, %s, %s) to %s", registry, repo, hash, localFile)

	var (
		w           io.Writer
		r           io.Reader
		stats       UpdateStats
		size        int64
		finalErr    error
		contentType string
	)

	// send out the maximum size as we understand it
	stats.Size = maxsize
	sendStats(prgchan, stats)

	opts := options(username, apiKey, client)

	// The OCI distribution spec only uses /blobs/ endpoint for layers or config, not index or manifest.
	// I have no idea why you cannot get a manifest or index from the /blobs endpoint, but so be it.
	image := fmt.Sprintf("%s/%s", registry, repo)
	ref, err := name.ParseReference(image)
	if err != nil {
		return 0, "", fmt.Errorf("parsing reference %q: %v", image, err)
	}

	// If hash is not empty:
	// if ref is of type Tag then add hash to the image
	// if ref is of type Digest, check if the given hash and the hash in reference are same
	if hash != "" {
		hash = checkAndCorrectHash(hash)
		if _, ok := ref.(name.Tag); ok {
			log.Infof("PullBlob: Adding hash %s to image %s", hash, image)
			image = fmt.Sprintf("%s@%s", image, hash)
			ref, err = name.ParseReference(image)
			if err != nil {
				return 0, "", fmt.Errorf("parsing reference %q: %v", image, err)
			}
		} else {
			d, ok := ref.(name.Digest)
			if !ok {
				return 0, "", fmt.Errorf("ref %s wasn't a tag or digest", image)
			}
			if checkAndCorrectHash(d.DigestStr()) != hash {
				return 0, "", fmt.Errorf("PullBlob: given hash %s is different from the hash in reference %s",
					hash, checkAndCorrectHash(d.DigestStr()))
			}
		}
	}

	// if we have only a tag, we know it is a manifest
	if _, ok := ref.(name.Tag); ok {
		log.Infof("PullBlob: requested manifest or had tag without hash, so just pulling root for %s", image)
		r, contentType, err = ociGetManifest(ref, opts)
		if err != nil {
			return 0, "", err
		}
	} else {
		// we had a hash, so get the actual layer, but fall back to manifest
		d, ok := ref.(name.Digest)
		if !ok {
			return 0, "", fmt.Errorf("ref %s wasn't a tag or digest", image)
		}
		log.Infof("PullBlob: had hash, so pulling blob for %s", image)
		layer, err := remote.Layer(d, opts...)
		if err != nil {
			return 0, "", fmt.Errorf("could not pull layer %s: %v", ref.String(), err)
		}
		// write the layer out to the file
		lr, err := layer.Compressed()
		if err != nil {
			// anything other than a 404 should return
			terr, ok := err.(*transport.Error)
			if !ok || terr.StatusCode != 404 {
				return 0, "", fmt.Errorf("could not get layer reader %s: %v", ref.String(), err)
			}
			// a 404 should try a manifest
			r, contentType, err = ociGetManifest(ref, opts)
			if err != nil {
				return 0, "", fmt.Errorf("could not retrieve as blob or manifest %s: %v", ref.String(), err)
			}
		} else {
			defer lr.Close()
			r = lr
		}
	}

	if localFile != "" {
		f, err := os.Create(localFile)
		if err != nil {
			return 0, "", fmt.Errorf("could not open local file %s for writing from %s: %v", localFile, ref.String(), err)
		}
		defer f.Close()
		w = f
	} else {
		w = os.Stdout
	}

	// get updates on downloads, convert and pass them to sendStats
	c := make(chan Update, 200)
	defer close(c)

	// copy from the readstream over the network to the writestream to the local file
	// we do this in a goroutine so we can catch the updates
	pw := &ProgressWriter{
		w:       w,
		updates: c,
		size:    maxsize,
	}

	go func() {
		// copy all of the data
		size, err := io.Copy(pw, r)
		if err != nil && err != io.EOF {
			log.Errorf("could not write to local file %s from %s: %v", localFile, ref.String(), err)
		}
		if err == nil {
			err = io.EOF
		}
		c <- Update{
			Total:    pw.size,
			Complete: size,
			Error:    err,
		}
	}()

	for update := range c {
		atomic.StoreInt64(&stats.Asize, update.Complete)
		atomic.StoreInt64(&stats.Size, update.Total)
		sendStats(prgchan, stats)
		size = update.Complete
		// any error means to stop
		if update.Error != nil {
			// EOF means we are at the end cleanly
			if update.Error == io.EOF {
				log.Infof("PullBlob(%s): download complete to %s size %d", image, localFile, size)
				finalErr = nil
			} else {
				log.Errorf("PullBlob(%s): error saving to %s: %v", image, localFile, update.Error)
				finalErr = update.Error
			}
			break
		}
	}

	return size, contentType, finalErr
}

// ociGetManifest get an OCI manifest
func ociGetManifest(ref name.Reference, opts []remote.Option) (io.Reader, string, error) {
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("error getting manifest: %v", err)
	}
	return bytes.NewReader(desc.Manifest), string(desc.MediaType), nil
}

// Pull downloads an entire image from a registry and saves it as a tar file at the provided location.
// Optionally, can use authentication of username and apiKey as provided, else defaults
// to the local user config. Also can use a given http client, else uses the default.
// Returns the manifest of the repo passed to it, the manifest of the resolved image,
// which either is the same as the repo manifest if an image, or the repo resolved
// from a manifest index, the size of the entire download, and error, if any.
func Pull(registry, repo, localFile, username, apiKey string, client *http.Client, prgchan NotifChan) ([]byte, []byte, int64, error) {
	// this is the manifest referenced by the image. If it is an index, it returns the index.
	var (
		manifestDirect, manifestResolved []byte
		img                              v1.Image
		size                             int64
		err                              error
		ref                              name.Reference
		stats                            UpdateStats
		image                            = fmt.Sprintf("%s/%s", registry, repo)
	)

	log.Infof("Pull(%s, %s) to %s", registry, repo, localFile)

	opts := options(username, apiKey, client)

	ref, _, img, manifestDirect, manifestResolved, size, err = manifestsDescImg(image, opts)
	if err != nil {
		return manifestDirect, manifestResolved, size, err
	}
	// record the target size and send it
	stats.Size = size
	sendStats(prgchan, stats)

	// create our local file and save to it
	localDir := path.Dir(localFile)
	err = os.MkdirAll(localDir, 0755)
	if err != nil {
		return manifestDirect, manifestResolved, size, fmt.Errorf("unable to create directory to store downloaded file %s: %v", localDir, err)
	}

	w, err := os.Create(localFile)
	if err != nil {
		return manifestDirect, manifestResolved, size, err
	}
	defer w.Close()

	tag, ok := ref.(name.Tag)
	if !ok {
		d, ok := ref.(name.Digest)
		if !ok {
			err := fmt.Errorf("Image name %s doesn't have a tag or digest", ref)
			return manifestDirect, manifestResolved, size, err
		}
		parts := strings.Split(d.DigestStr(), ":")
		if len(parts) != 2 {
			err := fmt.Errorf("Image name %s is malformed, expected: <name>@sha256:<hash>", d.String())
			return manifestDirect, manifestResolved, size, err
		}
		digestTag := fmt.Sprintf("dummyTag-%s", parts[1])
		tag = d.Repository.Tag(digestTag)
	}

	// get updates on downloads, convert and pass them to sendStats
	c := make(chan v1.Update, 200)
	defer close(c)

	// create a local file to write the output
	// this uses the v1/tarball to write it, which is fully compatible with docker save.
	// However, it is missing the "repositories" file, so we add it.
	// Eventially, we may want to move to an entire cache of the registry in the
	// OCI layout format.
	go func() {
		// we do not need to catch the return error, because tarball.WithProgress sends error updates on channels
		_ = tarball.Write(tag, img, w, tarball.WithProgress(c))
	}()

	for update := range c {
		atomic.StoreInt64(&stats.Asize, update.Complete)
		sendStats(prgchan, stats)
		// EOF means we are at the end
		if update.Error != nil && update.Error == io.EOF {
			break
		}
		if update.Error != nil {
			return manifestDirect, manifestResolved, size, fmt.Errorf("error saving to %s: %v", localFile, update.Error)
		}
	}

	return manifestDirect, manifestResolved, size, nil
}

func sendStats(prgChan NotifChan, stats UpdateStats) {
	if prgChan != nil {
		select {
		case prgChan <- stats:
		default: //ignore we cannot write
		}
	}
}

func max(x, y int64) int64 {
	if x < y {
		return y
	}
	return x
}

func options(username, apiKey string, client *http.Client) []remote.Option {
	// default to anonymous, unless we have auth credentials
	auth := authn.Anonymous
	// do we have auth to use?
	if username != "" || apiKey != "" {
		auth = authn.FromConfig(authn.AuthConfig{Username: username, Password: apiKey})
	}
	return []remote.Option{
		remote.WithAuth(auth),
		remote.WithTransport(client.Transport),
	}
}

// LayersFromManifest get the descriptors for layers from a raw image manifest
func LayersFromManifest(imageManifest []byte) ([]v1.Descriptor, error) {
	manifest, err := v1.ParseManifest(bytes.NewReader(imageManifest))
	if err != nil {
		return nil, fmt.Errorf("unable to parse manifest: %v", err)
	}
	return manifest.Layers, nil
}

// DockerHashFromManifest get the sha256 hash as a string from a raw image
// manifest. The "docker hash" is what is used for the image, i.e. the topmost
// layer.
func DockerHashFromManifest(imageManifest []byte) (string, error) {
	layers, err := LayersFromManifest(imageManifest)
	if err != nil {
		return "", fmt.Errorf("unable to get layers: %v", err)
	}
	if len(layers) < 1 {
		return "", fmt.Errorf("no layers found")
	}
	return layers[len(layers)-1].Digest.Hex, nil
}

//checkAndCorrectHash prepends algo "sha256:" if not already present.
func checkAndCorrectHash(hash string) string {
	return fmt.Sprintf("sha256:%s", strings.TrimPrefix(hash, "sha256:"))
}
