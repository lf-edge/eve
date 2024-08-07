use network_interface::{NetworkInterface, NetworkInterfaceConfig};

fn main() {
    let interfaces = NetworkInterface::show().unwrap();
    println!("{interfaces:#?}");
}
