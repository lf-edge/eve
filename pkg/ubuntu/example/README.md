# Example for pkg/ubuntu

How-to check for SBOM:
`git mv pkg/ubuntu/example pkg/ubuntu-example && git commit -m "ubuntu-example"`
`./tools/bump_dockerfiles.pl && git add -u && git commit -m "ubuntu-example bump dockerfiles"`
` make pkg/ubuntu pkg/ubuntu-example && make ubuntu-example-cache-export-docker-load | perl -ne 'print $1."\n" if (m/^Loaded image: (lfedge\/eve-ubuntu-example:\S+)$/);' | xargs syft -v | jq . | less `
