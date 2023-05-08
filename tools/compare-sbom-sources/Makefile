OUTDIR ?= bin
OUTFILE ?= $(OUTDIR)/compare-sbom-sources

.PHONY: build

build: $(OUTFILE)

$(OUTFILE): $(OUTDIR)
	go build -o $@ .

$(OUTDIR):
	mkdir -p $@