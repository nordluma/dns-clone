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

fn main() {
    println!("Hello, world!");
}
