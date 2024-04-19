/// Convenience type for a `Result` which return a generic `Error`
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct BytePacketBuffer {
    buf: [u8; 512],
    pos: usize,
}

impl BytePacketBuffer {
    const BUF_LEN: usize = 512;

    /// This gives us a fresh buffer for holding the packet contents, and a field for keeping track
    /// of where we are.
    fn new() -> Self {
        Self {
            buf: [0; Self::BUF_LEN],
            pos: 0,
        }
    }

    /// Current position in the buffer.
    fn pos(&self) -> usize {
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
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > Self::BUF_LEN {
            return Err("End of buffer".into());
        }

        Ok(&self.buf[start..start + len as usize])
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
            | ((self.read()? as u32) << 0);

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultCode {
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
            0 | _ => Self::NOERROR,
        }
    }
}

#[derive(Debug, Clone)]
struct DnsHeader {
    /// # Packet Identifier
    ///
    /// A random identifier is assigned to query packets. Response packets must reply with the same
    /// id. This is needed to differentiate responses due to the stateless nature of `UDP`.
    id: u16, // 16 bits
    /// # Recursion Desired
    ///
    /// Set by the sender of the request if the server should attempt to resolve the query
    /// recursively if it doesn't have an answer readily available.
    recursion_desired: bool, // 1 bit
    /// # Truncated Message
    ///
    /// Set to 1 if the message exceeds 512 bytes. Traditionally a hint that the query can be
    /// reissued using TCP, for which the length limitation doesn't apply.
    truncated_message: bool, // 1 bit
    /// # Authoritative Answer
    ///
    /// Set to 1 if the responding server is authoritative - that is, it "owns" - the domain
    /// queried.
    authoritative_answer: bool, // 1 bit
    /// # Operation Code
    ///
    /// Typically always 0, see [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035) for details.
    opcode: u8, // 4 bits
    /// # Query Response
    ///
    /// 0 for queries, 1 for response.
    response: bool, // 1 bit
    /// # Response Code
    ///
    /// Set by the server to indicate the status of the response, i.e. whether or not it was
    /// successful or failed, and in the latter case providing details about the cause of the
    /// failure.
    rescode: ResultCode, // 4 bits
    checking_disabled: bool, // 1 bit
    authed_data: bool,       // 1 bit
    /// # Reserved
    ///
    /// Originally reserved for later use, but now used for DNSSEC queries.
    z: bool, // 1 bit
    /// # Recursion Available
    ///
    /// Set by the server to indicate whether or not recursive queries are allowed.
    recursion_available: bool, // 1 bit
    /// # Question Count
    ///
    /// The number of entries in the `Question Section`
    questions: u16, // 16 bits
    /// # Answer Count
    ///
    /// The number of entries in the `Answer Section`
    answers: u16, // 16 bits
    /// # Authority Count
    ///
    /// The number of entries in the `Authority Section`
    authoritative_entries: u16, // 16 bits
    /// # Additional Count
    ///
    /// The number of entries in the `Additional Section`
    resource_entries: u16, // 16 bits
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum QueryType {
    Unknown(u16),
    A, // 1
}

impl QueryType {
    fn to_num(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
        }
    }

    fn from_num(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            _ => QueryType::Unknown(num),
        }
    }
}

fn main() {
    println!("Hello, world!");
}
