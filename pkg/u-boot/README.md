# u-boot

The `eve-u-boot` image ships only `/boot`, whose contents are copied to the
root of the ESP, plus the apk db for the SBOM:

* arm64: `u-boot.bin` (`rpi_arm64_defconfig`) and the Raspberry Pi firmware,
  DTBs, overlays and `config.txt` it needs.
* riscv64: `u-boot.bin` (`qemu-riscv64_smode_defconfig`), which QEMU loads with
  `-kernel`.
* amd64: nothing. x86 boots through UEFI and uses no u-boot, so `/boot` is an
  empty directory.
