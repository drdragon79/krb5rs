use std::net::{SocketAddr, ToSocketAddrs};

pub fn resolve_dns(domain: &str) -> std::io::Result<Option<SocketAddr>> {
    let ips = domain.to_socket_addrs()?
        .collect::<Vec<SocketAddr>>();
    if ips.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ips[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testresolution() {
    }
}