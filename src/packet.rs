use std::net::{Ipv4Addr, Ipv6Addr};

/// Convenience type for a `Result` which return a generic `Error`
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BytePacketBuffer {
    const BUF_LEN: usize = 512;

    /// This gives us a fresh buffer for holding the packet contents, and a field for keeping track
    /// of where we are.
    pub fn new() -> Self {
        Self {
            buf: [0; Self::BUF_LEN],
            pos: 0,
        }
    }

    /// Current position in the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps.
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position.
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    /// Read a single byte and move the position one step forward.
    fn read(&mut self) -> Result<u8> {
        if self.pos > Self::BUF_LEN {
            return Err("End of buffer".into());
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte without changing the buffer position.
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos > Self::BUF_LEN {
            return Err("End of buffer".into());
        }

        Ok(self.buf[pos])
    }

    /// Get a range of bytes.
    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > Self::BUF_LEN {
            return Err("End of buffer".into());
        }

        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes, stepping two steps forward.
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward.
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: reading domain names, taking labels into consideration.
    /// Will take something like `[3]www[6]google[3]com[0]` and append www.google.com to `outstr`.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position locally as opposed to
        // using the position within the struct. This allows us to move the shared position to a
        // point past our current qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a dot at the beginning
        // of the domain name we'll leave it empty for now and set it to "." at the end of the
        // first iteration.
        let mut delim = "";
        loop {
            // DNS Packets are untrusted data, so we need to be paranoid. Someone can craft a
            // packet with a cycle jump instructions. This guards against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall that labels start
            // with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bits set, it represents a jump to some other
            // offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current label. We don't need to
                // touch any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by updating our local
                // position variable.
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed
                jumped = true;
                jumps_performed += 1;

                continue;

            // The base scenario, where we're reading a single label and appending it to the
            // output:
            } else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain name are terminated by an empty label of length 0, so if the length is
                // zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them to the output
                // buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos > Self::BUF_LEN {
            return Err("End of buffer".into());
        }

        self.buf[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3F {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    fn from_num(num: u8) -> Self {
        match num {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => Self::NOERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    /// # Packet Identifier
    ///
    /// A random identifier is assigned to query packets. Response packets must reply with the same
    /// id. This is needed to differentiate responses due to the stateless nature of `UDP`.
    pub id: u16, // 16 bits
    /// # Recursion Desired
    ///
    /// Set by the sender of the request if the server should attempt to resolve the query
    /// recursively if it doesn't have an answer readily available.
    pub recursion_desired: bool, // 1 bit
    /// # Truncated Message
    ///
    /// Set to 1 if the message exceeds 512 bytes. Traditionally a hint that the query can be
    /// reissued using TCP, for which the length limitation doesn't apply.
    pub truncated_message: bool, // 1 bit
    /// # Authoritative Answer
    ///
    /// Set to 1 if the responding server is authoritative - that is, it "owns" - the domain
    /// queried.
    pub authoritative_answer: bool, // 1 bit
    /// # Operation Code
    ///
    /// Typically always 0, see [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035) for details.
    pub opcode: u8, // 4 bits
    /// # Query Response
    ///
    /// 0 for queries, 1 for response.
    pub response: bool, // 1 bit
    /// # Response Code
    ///
    /// Set by the server to indicate the status of the response, i.e. whether or not it was
    /// successful or failed, and in the latter case providing details about the cause of the
    /// failure.
    pub rescode: ResultCode, // 4 bits
    pub checking_disabled: bool, // 1 bit
    pub authed_data: bool,       // 1 bit
    /// # Reserved
    ///
    /// Originally reserved for later use, but now used for DNSSEC queries.
    pub z: bool, // 1 bit
    /// # Recursion Available
    ///
    /// Set by the server to indicate whether or not recursive queries are allowed.
    pub recursion_available: bool, // 1 bit
    /// # Question Count
    ///
    /// The number of entries in the `Question Section`
    pub questions: u16, // 16 bits
    /// # Answer Count
    ///
    /// The number of entries in the `Answer Section`
    pub answers: u16, // 16 bits
    /// # Authority Count
    ///
    /// The number of entries in the `Authority Section`
    pub authoritative_entries: u16, // 16 bits
    /// # Additional Count
    ///
    /// The number of entries in the `Additional Section`
    pub resource_entries: u16, // 16 bits
}

impl DnsHeader {
    fn new() -> Self {
        Self {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3 as u8)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    Unknown(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 3
    MX,    // 4
    AAAA,  // 5
}

impl QueryType {
    fn as_num(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    fn from_num(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::Unknown(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let type_num = self.qtype.as_num();
        buffer.write_u16(type_num)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        let record = match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr) & 0xFF) as u8,
                );

                Self::A { domain, addr, ttl }
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Self::NS {
                    domain,
                    host: ns,
                    ttl,
                }
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Self::CNAME {
                    domain,
                    host: cname,
                    ttl,
                }
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Self::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                }
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Self::AAAA { domain, addr, ttl }
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;

                Self::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                }
            }
        };

        Ok(record)
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.as_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.as_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.as_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.as_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.as_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::Unknown { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// # Header
    ///
    /// Information about the query/response.
    pub header: DnsHeader,
    /// # Question Section
    ///
    /// In practice only a single question indicating the query name (domain) and the record type
    /// of interest.
    pub questions: Vec<DnsQuestion>,
    /// # Answer Section
    ///
    /// The relevant records of the request type.
    pub answers: Vec<DnsRecord>,
    /// # Authority Section
    ///
    /// A list of name servers (NS records), used for resolving queries recursively.
    pub authorities: Vec<DnsRecord>,
    /// # Additional Section
    ///
    /// Additional records, that might be useful. For instance, the corresponding A records for NS
    /// records.
    pub resources: Vec<DnsRecord>,
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::Unknown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in &self.answers {
            rec.write(buffer)?;
        }

        for rec in &self.authorities {
            rec.write(buffer)?;
        }

        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    /// It's useful to be able to pick a random `A` record from a packet. When
    /// we get multiple IP's for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    /// A helper function which returns an iterator over all name servers in the
    /// authorities section, represented as (domain, host) tuples.
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // In practice, these are always `NS` records in well formed
            // packages. Convert the `NS` records to a tuple which has only the
            // data we need to work with.
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Discard servers which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// We'll use the fact that name servers often bundle the corresponding `A`
    /// records when replying to an `NS` query to implement a function that
    /// returns the actual IP for an NS record if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            // Now we need to look for a matching `A` record in the additional
            // section. Since we just want the first valid record, we can just
            // build a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Filter for `A` records where the domain matches the host
                    // of the `NS` record that we are currently processing
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            // Finally, pick the first valid entry
            .next()
    }

    /// However, not all name servers are that nice. In certain cases there
    /// won't be any `A` records in the additional section, and we'll have to
    /// perform *another* lookup in the midst. For this, we introduce a method
    /// for returning the host name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            .map(|(_, host)| host)
            // Pick the first valid entry
            .next()
    }
}
