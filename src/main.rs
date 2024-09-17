use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_service(1080).await?;
    Ok(())
}

async fn start_service(port: u16) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        process_local_stream(stream).await?;
    }
}

// Do socks5 handshake, and based on domain name, either
// block the request or fullfill the request
async fn process_local_stream(tcp_stream: TcpStream) -> Result<(), std::io::Error> {
    Ok(())
}
