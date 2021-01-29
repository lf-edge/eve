# ver-update

This ver-update directory has scripts to help update Dockerfile package versions.

## Sample Usage

These were the steps to update `pkg/eve/Dockerfile.in` from 3.12 to 3.13.0.

* make -C build-tools/ver-update clean
* make -C build-tools/ver-update alpine
* grep pkg/eve/Dockerfile.in build-tools/ver-update/out-alp-ver-diff

This gives you:

* pkg/eve/Dockerfile.in coreutils 8.32-r0 8.32-r2
* pkg/eve/Dockerfile.in qemu-img 5.0.0-r2 5.2.0-r2
* pkg/eve/Dockerfile.in tar 1.32-r1 1.33-r1
* pkg/eve/Dockerfile.in uboot-tools 2020.04-r0 2021.01-r0

You then modify pkg/eve/Dockerfile.in. You need to update the FROM line
and the versions manually. Then ```git diff``` gives you:

```diff
-FROM alpine:3.12 as tools
+FROM alpine:3.13.0 as tools
 RUN mkdir -p /out/etc/apk /out/boot && cp -r /etc/apk/* /out/etc/apk/
-RUN apk add --no-cache --initdb -p /out qemu-img=5.0.0-r2 tar=1.32-r1 uboot-tools=2020.04-r0 coreutils=8.32-r0
+RUN apk add --no-cache --initdb -p /out qemu-img=5.2.0-r2 tar=1.33-r1 uboot-tools=2021.01-r0 coreutils=8.32-r2
 # hadolint ignore=DL3006
 FROM MKISO_TAG as iso
```

## See Also

docs/CI-CD.md
