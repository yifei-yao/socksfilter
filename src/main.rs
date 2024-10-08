use qfilter::Filter;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream},
    time::sleep,
};

use std::{
    fs::File,
    io::{self, BufRead, Error, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hash_set = Arc::new(read_denylist("denylist.txt")?);
    start_service(1080, hash_set).await?;
    Ok(())
}

struct DomainSet {
    set: Filter,
}

impl DomainSet {
    fn new(capacity: u64) -> Self {
        Self {
            set: Filter::new(capacity, 0.000000001).unwrap(),
        }
    }

    fn insert(&mut self, s: &str) {
        self.set.insert(s).unwrap();
    }

    fn contains(&self, s: &str) -> bool {
        self.set.contains(s)
    }
}

fn read_denylist(path: &str) -> io::Result<DomainSet> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut valid_entry_count = 0;

    for line in reader.lines() {
        let line = line?;
        let line = match line.split_once('#') {
            Some((before_comment, _)) => before_comment,
            None => &line,
        };
        let line = line.trim().to_lowercase();
        if !line.is_empty() {
            valid_entry_count += 1;
        }
    }

    let mut filter = DomainSet::new(valid_entry_count);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let line = match line.split_once('#') {
            Some((before_comment, _)) => before_comment,
            None => &line,
        };
        let line = line.trim().to_lowercase();
        if !line.is_empty() {
            filter.insert(&line);
        }
    }
    Ok(filter)
}

async fn start_service(port: u16, denylist: Arc<DomainSet>) -> Result<(), Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let denylist = denylist.clone();
        tokio::spawn(async move {
            if let Err(e) = process_local_stream(stream, port, denylist).await {
                eprintln!("{e}");
            }
        });
    }
}

fn in_denylist(domain: &str, denylist: &DomainSet) -> bool {
    let mut parts = domain.rsplit('.');
    let mut current = if let Some(part) = parts.next() {
        part.to_owned()
    } else {
        return false;
    };
    for part in parts {
        current = format!("{}.{}", part, current);
        if denylist.contains(&current) {
            println!("Domain: {domain} blocked");
            return true;
        }
    }
    false
}

// Does socks5 handshake, and based on domain name, either
// blocks the request or fullfills the request
async fn process_local_stream(
    tcp_stream: TcpStream,
    port: u16,
    denylist: Arc<DomainSet>,
) -> Result<(), std::io::Error> {
    // Communicate request type
    let mut tcp_stream = BufStream::new(tcp_stream);
    if tcp_stream.read_u8().await? != 5 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid version"));
    }
    let n_mehtods = tcp_stream.read_u8().await?;
    if n_mehtods == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid nmethods"));
    }
    let mut buffer = vec![0u8; n_mehtods as usize];
    tcp_stream.read_exact(&mut buffer).await?;

    if !buffer.contains(&0) {
        eprintln!("{:?}", buffer);
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS5 request"));
    }
    tcp_stream.write_all(&[5, 0]).await?;
    tcp_stream.flush().await?;

    // Read target address
    let mut buffer = [0u8; 3];
    tcp_stream.read_exact(&mut buffer).await?;
    if buffer != [5, 1, 0] {
        // eprintln!("{:?}", buffer);
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS5 request"));
    }
    let socket_addr = read_addr(&mut tcp_stream).await?;

    if let Address::Domain(domain) = &socket_addr.address {
        if in_denylist(domain, &denylist) {
            sleep(Duration::from_secs(300)).await;
            return Ok(());
        }
    }

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
    tcp_stream.flush().await?;
    if let Ok(mut remote_stream) = remote {
        copy_bidirectional(&mut tcp_stream.into_inner(), &mut remote_stream).await?;
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
    match socksaddr.address {
        Address::V4(ipv4) => TcpStream::connect((ipv4, socksaddr.port)).await,
        Address::V6(ipv6) => TcpStream::connect((ipv6, socksaddr.port)).await,
        Address::Domain(domain) => TcpStream::connect((domain, socksaddr.port)).await,
    }
}

async fn read_addr(reader: &mut BufStream<TcpStream>) -> Result<SocksAddr, Error> {
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
            let length = reader.read_u8().await?;
            let mut domain_buf = vec![0u8; length as usize];
            reader.read_exact(&mut domain_buf).await?;
            let domain_name = String::from_utf8_lossy(&domain_buf).to_string();
            let port = reader.read_u16().await?;
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
