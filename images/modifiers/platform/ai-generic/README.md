# ai-generic platform modifier

`PLATFORM=ai-generic` is eve-k (`HV=k`) on x86_64 with NVIDIA discrete GPUs.
`ai-generic.yq` is applied to the rootfs manifest after the `HV=k` modifier;
the yq version EVE pins does not accept comments in expression files, so the
reasons for each line live here.

- `with(select(.services[] | select(.name == "pillar")); ...)` applies the
  rest to a manifest that runs pillar, i.e. the rootfs, and leaves every
  other manifest as it is. `find-modifiers-installer` composes the installer
  with this file too, and the installer runs no pillar: unscoped, it would
  carry the 431 MB NVIDIA userland for nothing (and gain an empty
  `services:`).
- `.init += ["NVIDIA_TAG"]` adds the NVIDIA userland (the ai-generic variant
  of `pkg/nvidia`, `build-ai-generic.yml`). The NVIDIA host tools are glibc
  binaries, like everything else on the Ubuntu based rootfs: `nv-init.sh`
  runs them inside pillar from `device-steps.sh`, and k3s's containerd in the
  kube container executes `/opt/vendor/nvidia/bin/nvidia-container-runtime`
  and the CDI hooks, all with the glibc of those containers.

The kernel (`ai` config flavour: hwe plus the NVIDIA modules and GSP
firmware) is selected in `kernel-version.mk`. The NVIDIA kernel module, the
userland in `pkg/nvidia` and the GSP firmware must be the same driver
version; see `pkg/nvidia/README-ai-generic.md`.
