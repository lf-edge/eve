OUTDIR ?= bin
OUTFILE ?= $(OUTDIR)/dockerfile-add-scanner

.PHONY: build

build: $(OUTFILE)

$(OUTFILE): $(OUTDIR)
	go build -tags dfaddgit -o $@ .

$(OUTDIR):
	mkdir -p $@