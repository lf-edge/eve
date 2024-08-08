fn main() {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        use cc::Build;
        use std::path::Path;
        const TARGET_MACOS: &str = "macos";
        const TARGET_IOS: &str = "ios";
        const TARGET_FREEBSD: &str = "freebsd";
        const TARGET_OPENBSD: &str = "openbsd";
        const TARGET_NETBSD: &str = "netbsd";
        const TARGET_DRAGONFLY: &str = "dragonfly";

        // check cross-compile target. Only build lladdr.o when actually targeting UNIX.
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
        if [
            TARGET_MACOS,
            TARGET_IOS,
            TARGET_FREEBSD,
            TARGET_OPENBSD,
            TARGET_NETBSD,
            TARGET_DRAGONFLY,
        ]
        .contains(&target_os.as_str())
        {
            let path = Path::new("src")
                .join("target")
                .join("unix")
                .join("ffi")
                .join("lladdr.c");

            Build::new().file(path).compile("ffi");
        }
    }
}
