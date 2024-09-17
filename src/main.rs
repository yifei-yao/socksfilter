use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use std::{
    io::{self, Error, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_service(1080).await?;
    Ok(())
}

async fn start_service(port: u16) -> Result<(), Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = process_local_stream(stream, port).await {
                eprintln!("{e}");
            }
        });
    }
}

// Does socks5 handshake, and based on domain name, either
// blocks the request or fullfills the request
async fn process_local_stream(mut tcp_stream: TcpStream, port: u16) -> Result<(), std::io::Error> {
    // Communicate request type
    let mut buffer = [0u8; 3];
    tcp_stream.read_exact(&mut buffer).await?;
    if buffer != [5, 1, 0] {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS5 request"));
    }
    tcp_stream.write_all(&[5, 0]).await?;

    // Read target address
    let mut buffer = [0u8; 3];
    tcp_stream.read_exact(&mut buffer).await?;
    if buffer != [5, 1, 0] {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS5 request"));
    }
    let socket_addr = read_addr(&mut tcp_stream).await?;

    // Todo: filter out domains

    // Proceed to forward the conneciton
    let remote = connect_remote(socket_addr.clone()).await;
    tcp_stream.write_u8(5).await?;
    let reply = match &remote {
        Ok(_) => 0,
        Err(e) => match e.kind() {
            ErrorKind::ConnectionRefused => 5,
            ErrorKind::AddrNotAvailable => 3,
            ErrorKind::TimedOut => 6,
            ErrorKind::ConnectionReset => 5,
            ErrorKind::Unsupported => 7,
            _ => 1,
        },
    };
    tcp_stream.write_u8(reply).await?;
    tcp_stream.write_u8(0).await?;
    tcp_stream.write_u8(1).await?;
    tcp_stream.write_all(&[127, 0, 0, 1]).await?;
    tcp_stream.write_u16(port).await?;
    if let Ok(mut remote_stream) = remote {
        copy_bidirectional(&mut tcp_stream, &mut remote_stream).await?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct SocksAddr {
    address: Address,
    port: u16,
}

#[derive(Clone, Debug)]
enum Address {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

async fn connect_remote(socksaddr: SocksAddr) -> io::Result<TcpStream> {
    println!("{:?}", socksaddr);
    match socksaddr.address {
        Address::V4(ipv4) => TcpStream::connect((ipv4, socksaddr.port)).await,
        Address::V6(ipv6) => TcpStream::connect((ipv6, socksaddr.port)).await,
        Address::Domain(domain) => TcpStream::connect((domain, socksaddr.port)).await,
    }
}

async fn read_addr(reader: &mut TcpStream) -> Result<SocksAddr, Error> {
    let atyp = reader.read_u8().await?;
    match atyp {
        1 => {
            println!("Ipv4 requested");
            let mut ipv4_buf = [0u8; 4];
            reader.read_exact(&mut ipv4_buf).await?;
            let ipv4 = Ipv4Addr::from(ipv4_buf);
            let port = reader.read_u16().await?;
            Ok(SocksAddr {
                address: Address::V4(ipv4),
                port,
            })
        }
        3 => {
            println!("Domain name requested");
            let length = reader.read_u8().await?;
            let mut domain_buf = vec![0u8; length as usize];
            reader.read_exact(&mut domain_buf).await?;
            let domain_name = String::from_utf8_lossy(&domain_buf).to_string();
            let port = reader.read_u16().await?;
            println!("Connecting to domain: {} on port {}", domain_name, port);
            Ok(SocksAddr {
                address: Address::Domain(domain_name),
                port,
            })
        }
        4 => {
            println!("Ipv6 requested");
            let mut ipv6_buf = [0u8; 16];
            reader.read_exact(&mut ipv6_buf).await?;
            let ipv6 = Ipv6Addr::from(ipv6_buf);
            let port = reader.read_u16().await?;
            Ok(SocksAddr {
                address: Address::V6(ipv6),
                port,
            })
        }
        _ => Err(Error::new(ErrorKind::InvalidData, "Unsupported ATYP")),
    }
}
