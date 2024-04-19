use std::io::Read;

use dns_clone::packet::{BytePacketBuffer, DnsPacket, Result};

fn main() -> Result<()> {
    let mut f = std::fs::File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }

    for rec in packet.answers {
        println!("{:#?}", rec);
    }

    for rec in packet.authoritives {
        println!("{:#?}", rec);
    }

    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
