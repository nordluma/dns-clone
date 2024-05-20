use std::net::UdpSocket;

use dns_clone::packet::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType, Result, ResultCode};

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for
    // serving request is initiated.
    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("An error occurred: {}", e);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // forward requests to googles public DNS server
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
    DnsPacket::from_buffer(&mut res_buffer)
}

/// Handle a single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<()> {
    // With a socket ready, we can read a packet. This will block until one is
    // received.
    let mut req_buffer = BytePacketBuffer::new();

    // The `recv_from` function will write the data into the provided buffer,
    // and return the length of the data as well as the source addr. We're not
    // interested in the length, but we need to keep track of the source in
    // order to send our reply later on.
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into a
    // `DnsPacket`.
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Create and init the response packet
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // In the normal case, exactly one question is present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Since all is set up and as expected, the query can be forwarded to
        // the target server. There's always the possibility that the query will
        // fail, in which case the `SERVFAIL` response code is set to indicate
        // as much to the client. If rather everything goes as planned, the
        // question and response records are copied into our response packet.
        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }

            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }

            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        // Being mindful of how unreliable input data from arbitrary senders
        // can be, we need to make sure that a question is actually present. If
        // not, we return `FORMERR` to indicate that the sender did something
        // wrong.
        packet.header.rescode = ResultCode::FORMERR;
    }

    // Last thing remaining is to encode our response and send it
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}
