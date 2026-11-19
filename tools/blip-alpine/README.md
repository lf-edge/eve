# blip-alpine

A tool that bumps the Alpine packages of EVE and opens a pull request for it.
It can also tell which packages a bump would change.

## Usage

```bash
go build
./blip-alpine blip          # bump, push and open a draft pull request
./blip-alpine blip -d       # dry run
./blip-alpine compare       # list the packages that Alpine has in another build
./blip-alpine list-apks docker://lfedge/eve-alpine:<tag>  # packages of a mirror
./blip-alpine clone <directory>  # check out EVE's master, without history
```

`blip` and `compare` work on the EVE checkout that they are started in.
`clone` makes one.

## blip

`blip` makes `pkg/alpine` build on top of the current `lfedge/eve-alpine`
image and then updates the image tags in every Dockerfile that is built from
eve-alpine, or from a package whose hash changed because of that, until
nothing changes any more. The result is one commit that touches nothing but
`lfedge/eve-*` image tags in `FROM` lines and `ARG` defaults.

It first compares the packages the way `compare` does. If none differs,
there is nothing to bump: it says so, closes the pull request of an earlier
run if that is still open, and stops.

The EVE checkout needs a remote `origin` that points to the upstream
repository.

Otherwise a normal run does the following:

* fetches `origin`
* switches to the branch `blip-alpine` and resets it to `origin/master`;
  **uncommitted changes to tracked files are lost**
* bumps the Dockerfiles and commits the result
* force-pushes the branch to the `eve` fork of the GitHub user that the
  token belongs to
* opens a draft pull request from that branch, or gives the one that is open
  already a new description; the changelog notes of the description list
  the packages that differ

With `-d` (`--dry-run`) it only bumps and commits on the branch that is
checked out, whatever the comparison says: no branch switch, no reset, no
push and no pull request. It still asks GitHub for the user's e-mail
address, so it needs the token too.

## compare

`compare` (or `comp`) lists the Alpine packages that the eve-alpine image of
the checkout has in another build than Alpine has now. These are the
packages that a bump would bring up to date:

```text
pkgs in different versions:
- gnutls
- libcrypto3
- openssl
```

It compares the mirror of Alpine packages inside the image
`lfedge/eve-alpine:<tag>`, where the tag is the hash of `pkg/alpine` in the
checkout, with the repositories of Alpine at `dl-cdn.alpinelinux.org`:

* The image says which mirrors it has. Its `/etc/apk/repositories` names one
  for each version of Alpine, as in `/mirror/3.22/x86_64/..`. Older versions
  of EVE have a mirror of Alpine 3.16, and some of them one of Alpine edge
  as well.
* `pkg/alpine/mirrors/<version>/` in the checkout says which repositories of
  a version are mirrored, like `main` and `community`.
* A package is the same on both sides if the mirror has it with the checksum
  that Alpine has for that name. The mirror keeps the old versions of a
  package, so it is enough that one of them is the one of Alpine. A package
  that only one side has is left out.

The image is not pulled. Only the files that are needed are read from the
registry, without a login, which takes a few seconds, and some more for a
version of EVE that has a mirror of Alpine edge. The image has to be on
Docker Hub: for a while after a change to `pkg/alpine` is merged, the image
of master is not there yet.

Limits:

* It compares for the architecture of the machine that it runs on.
* A difference does not say which side is newer. The mirror of 13.4-stable
  has a newer `ca-certificates` than Alpine 3.16, for example, and that is
  listed on every run.
* A package that is still in the mirror but not needed any more is listed
  once Alpine updates it, although a bump would not fetch it.

## list-apks

`list-apks` (or `la`, `ls`) prints the names of the packages of an index. It
takes one of:

* `docker://<image>` for the mirror of an eve-alpine image, as in
  `docker://lfedge/eve-alpine:<tag>`. The tag is the one in the
  `FROM lfedge/eve-alpine:` lines of the Dockerfiles. For now this reads the
  mirror of Alpine 3.22 for x86_64 only, which older images do not have,
  `lfedge/eve-alpine:latest` among them.
* `https://...` for an index of a repository, as in
  `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz`

A mirror lists a package once for every version of it that it has.

## clone

`clone <directory>` (or `checkout`, `co`) checks out EVE into a directory,
for `blip` and `compare` to work in a checkout of their own:

```bash
./blip-alpine clone ~/eve-blip
```

It clones `https://github.com/lf-edge/eve.git` with go-git, so it needs no
git binary and no token, and it takes as little as go-git can fetch: the
newest commit of `master` with its files. No history comes along, no other
branch, no tag and no submodule. That is a download of about 55 MiB instead
of about 430 MiB, and a checkout of about 770 MiB, nearly all of it the
files.

The files are all there because `blip` needs them: the tag of a package
image tells whether a file of the package is changed, and for that every
file of the package has to be there.

The remote `origin` of the checkout is the upstream repository, as `blip`
needs it. A later fetch in it brings only what is new on `master`.

The directory must not be there yet, or be empty. If the clone fails, the
directory is as it was before.

## GitHub token

Only `blip` needs a token: `compare`, `list-apks` and `clone` read what
everybody may read.

Put the token into `~/.config/blip-alpine.json`:

```json
{
  "token": "ghp_..."
}
```

The file holds a secret, so make it readable for you alone
(`chmod 600 ~/.config/blip-alpine.json`).

Without that file the tool takes the token from where the `gh` command has
it: the environment variable `GH_TOKEN` or `GITHUB_TOKEN`, or the login of
`gh auth login`.

Create the token at <https://github.com/settings/tokens> as a
*personal access token (classic)* with these scopes:

* `public_repo` to push the branch to the fork and to open the pull request
* `workflow` because GitHub refuses a push that brings changes to
  `.github/workflows` along without it, and the commits of master do that
  from time to time
* `user:email` to read the e-mail address for the `Signed-off-by` line of
  the commit

A fine-grained token does not work as long as the pull request goes to a
repository that the user of the token does not own.

The GitHub user of the token needs:

* a fork of the repository named `eve`
* a verified primary e-mail address
