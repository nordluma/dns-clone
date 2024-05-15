use std::net::UdpSocket;

use dns_clone::packet::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType, Result};

fn main() -> Result<()> {
    // query for "google.com"
    let qname = "google.com";
    let qtype = QueryType::A;

    // use googles public DNS server
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 8686))?;

    // Build query packet. We have to remember to set the `recursion_desired`
    // flag. The packet id will be arbitrary.
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // use the `write` method to write the packet to a buffer.
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // send the packet to the server using our udp socket
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // create a new `BytePacketBuffer` for receiving the response and ask the
    // socket to write the response directly to the buffer
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // `DnsPacket::from_buffer` is used to parse the packet after which we can
    // print the response
    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }

    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }

    for rec in res_packet.authoritives {
        println!("{:#?}", rec);
    }

    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
