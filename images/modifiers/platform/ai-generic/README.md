# ai-generic platform modifier

`PLATFORM=ai-generic` is eve-k (`HV=k`) on x86_64 with NVIDIA discrete GPUs.
`ai-generic.yq` is applied to the rootfs manifest after the `HV=k` modifier;
the yq version EVE pins does not accept comments in expression files, so the
reasons for each line live here.

- `with(select(.services[] | select(.name == "pillar")); ...)` applies the
  rest to a manifest that runs pillar, i.e. the rootfs, and leaves every
  other manifest as it is. `find-modifiers-installer` composes the installer
  with this file too, and the installer runs no pillar: unscoped, it would
  carry glibc for nothing (and gain an empty `services:`).
- `.init += ["GLIBC_TAG"]` adds the GNU C runtime (`pkg/glibc`), which the
  NVIDIA host tools are linked against.
- pillar `binds.add` of `/usr/lib64` and `/usr/lib/x86_64-linux-gnu`:
  `nv-init.sh` runs inside pillar (Alpine/musl) from `device-steps.sh` and
  executes NVIDIA's glibc binaries. Without the host's glibc runtime in the
  container they fail to exec with exit 127. Alpine has neither path, so
  nothing is shadowed; `/lib64` holds the loader every glibc binary names as
  its interpreter. The append keeps pillar's existing `debug-tools` bind.
- kube `binds.add` of the same two paths: k3s's containerd runs in the kube
  container and executes `/opt/vendor/nvidia/bin/nvidia-container-runtime`
  and the CDI hooks, also glibc. Without them containerd can only report
  "unable to retrieve OCI runtime error", because the runtime never started.

The kernel (`ai` config flavour: hwe plus the NVIDIA modules and GSP
firmware) is selected in `kernel-version.mk`.
