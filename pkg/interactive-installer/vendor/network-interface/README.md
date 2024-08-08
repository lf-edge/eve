<div>
  <h1 align="center">network-interface</h1>
  <h4 align="center">
    Retrieve system's Network Interfaces/Adapters on Android, FreeBSD, Linux, macOS, iOS and Windows
    on a standarized manner
  </h4>
</div>

<div align="center">

  [![Crates.io](https://img.shields.io/crates/v/network-interface.svg)](https://crates.io/crates/network-interface)
  [![Documentation](https://docs.rs/network-interface/badge.svg)](https://docs.rs/network-interface)
  ![Build](https://github.com/EstebanBorai/network-interface/workflows/build/badge.svg)
  ![Clippy](https://github.com/EstebanBorai/network-interface/workflows/clippy/badge.svg)
  ![Formatter](https://github.com/EstebanBorai/network-interface/workflows/fmt/badge.svg)

</div>

> This crate is under development, feel free to contribute on [GitHub](https://github.com/EstebanBorai/network-interface). API and implementation is subject to change.

The main goal of `network-interface` crate is to retrieve system's Network
Interfaces in a standardized manner.

_standardized manner_ means that every supported platform must expose the same
API and no further changes to the implementation are required to support such
platform.

## Usage
```rust
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;

fn main() {
    let network_interfaces = NetworkInterface::show().unwrap();

    for itf in network_interfaces.iter() {
        println!("{:?}", itf);
    }
}
```

<details>
  <summary>Output</summary>

```
NetworkInterface { name: "lo", addr: Some(V4(V4IfAddr { ip: 127.0.0.1, broadcast: Some(127.0.0.1), netmask: Some(255.0.0.0) })) }
NetworkInterface { name: "wlp1s0", addr: Some(V4(V4IfAddr { ip: 192.168.0.16, broadcast: Some(192.168.0.255), netmask: Some(255.255.255.0) })) }
NetworkInterface { name: "wg0", addr: Some(V4(V4IfAddr { ip: 10.8.0.4, broadcast: Some(10.8.0.4), netmask: Some(255.255.255.0) })) }
NetworkInterface { name: "docker0", addr: Some(V4(V4IfAddr { ip: 172.17.0.1, broadcast: Some(172.17.255.255), netmask: Some(255.255.0.0) })) }
NetworkInterface { name: "lo", addr: Some(V6(V6IfAddr { ip: ::1, broadcast: None, netmask: Some(ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) })) }
NetworkInterface { name: "wlp1s0", addr: Some(V6(V6IfAddr { ip: <redacted>, broadcast: None, netmask: Some(ffff:ffff:ffff:ffff::) })) }
NetworkInterface { name: "docker0", addr: Some(V6(V6IfAddr { ip: <redacted>, broadcast: None, netmask: Some(ffff:ffff:ffff:ffff::) })) }
NetworkInterface { name: "veth9d2904f", addr: Some(V6(V6IfAddr { ip: <redacted>, broadcast: None, netmask: Some(ffff:ffff:ffff:ffff::) })) }
NetworkInterface { name: "vethcdd79af", addr: Some(V6(V6IfAddr { ip: <redacted>, broadcast: None, netmask: Some(ffff:ffff:ffff:ffff::) })) }
```
</details>

## Release

In order to create a release you must push a Git tag as follows

```sh
git tag -a <version> -m <message>
```

**Example**

```sh
git tag -a v0.1.0 -m "First release"
```

> Tags must follow semver conventions
> Tags must be prefixed with a lowercase `v` letter.

Then push tags as follows:

```sh
git push origin main --follow-tags
```

## Contributing

Every contribution to this project is welcome. Feel free to open a pull request,
an issue or just by starting this project.

## License

Distributed under the terms of both the MIT license and the Apache License (Version 2.0)
