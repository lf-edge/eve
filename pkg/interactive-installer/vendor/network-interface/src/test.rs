#[allow(unused_imports)]
use crate::{NetworkInterface, NetworkInterfaceConfig};

#[test]
fn show_network_interfaces() {
    let network_interfaces = NetworkInterface::show().unwrap();

    println!("{network_interfaces:#?}");
    assert!(network_interfaces.len() > 1);
}
