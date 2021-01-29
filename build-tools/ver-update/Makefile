# build-tools/ver-update/Makefile

# uses last definition
ALP_BASE_OS = lfedge/eve-alpine:5.20.0
ALP_BASE_OS = alpine:3.13.0
UBU_BASE_OS = cassandra:3.11.9
UBU_BASE_OS = ubuntu:18.04
UBU_BASE_OS = ubuntu:20.04

# Alpine/apk
OUT_ALP_VER_DIFF     = out-alp-ver-diff
OUT_ALP_FILE_PKG_VER = out-alp-file-pkg
OUT_ALP_LATEST       = out-alp-latest

# Ubuntu/apt
OUT_UBU_VER_DIFF     = out-ubu-ver-diff
OUT_UBU_FILE_PKG_VER = out-ubu-file-pkg
OUT_UBU_LATEST       = out-ubu-latest

all: alpine ubuntu
	: $@: Succeeded

alpine: $(OUT_ALP_VER_DIFF)
	wc -l $(OUT_ALP_VER_DIFF)
	: $@: Succeeded

ubuntu: $(OUT_UBU_VER_DIFF)
	wc -l $(OUT_UBU_VER_DIFF)
	: $@: Succeeded

# Alpine/apk

$(OUT_ALP_VER_DIFF):: $(OUT_ALP_LATEST) $(OUT_ALP_FILE_PKG_VER)
$(OUT_ALP_VER_DIFF)::
	./gen-ver-diff $(OUT_ALP_LATEST) $(OUT_ALP_FILE_PKG_VER) > $@.tmp
	mv -f $@.tmp $@
	: $@: Succeeded

$(OUT_ALP_FILE_PKG_VER): gen-alp-file-pkg
	./gen-alp-file-pkg > $@.tmp
	mv -f $@.tmp $@
	: $@: Succeeded

$(OUT_ALP_LATEST): gen-alp-latest Makefile $(OUT_ALP_FILE_PKG_VER)
	: $@: Begin: ALP_BASE_OS=$(ALP_BASE_OS)
	./gen-alp-latest $(ALP_BASE_OS) > $@.tmp
	mv -f $@.tmp $@
	: $@: Succeeded

# Ubuntu/apt

$(OUT_UBU_VER_DIFF):: $(OUT_UBU_LATEST) $(OUT_UBU_FILE_PKG_VER)
$(OUT_UBU_VER_DIFF)::
	./gen-ver-diff $(OUT_UBU_LATEST) $(OUT_UBU_FILE_PKG_VER) > $@.tmp
	mv -f $@.tmp $@
	: $@: Succeeded

$(OUT_UBU_FILE_PKG_VER): gen-ubu-file-pkg
	./gen-ubu-file-pkg > $@.tmp
	mv -f $@.tmp $@
	: $@: Succeeded

$(OUT_UBU_LATEST): gen-ubu-latest Makefile $(OUT_UBU_FILE_PKG_VER)
	: $@: Begin: UBU_BASE_OS=$(UBU_BASE_OS)
	./gen-ubu-latest $(UBU_BASE_OS) > $@.tmp
	mv -f $@.tmp $@
	: $@: Succeeded

# misc

.PHONY: all clean test

clean::
	rm -f $(OUT_ALP_VER_DIFF) $(OUT_ALP_FILE_PKG_VER) $(OUT_ALP_LATEST)
	rm -f $(OUT_UBU_VER_DIFF) $(OUT_UBU_FILE_PKG_VER) $(OUT_UBU_LATEST)
