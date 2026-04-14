use crate::protocol::{DnsError, U16_SIZE, U32_SIZE};

pub struct PacketBuffer<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> PacketBuffer<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8, DnsError> {
        if self.pos >= self.buf.len() {
            return Err(DnsError::TooShort);
        }
        let val = self.buf[self.pos];
        self.pos += 1;
        Ok(val)
    }

    pub fn read_u16(&mut self) -> Result<u16, DnsError> {
        if self.pos + U16_SIZE > self.buf.len() {
            return Err(DnsError::TooShort);
        }
        let val = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += U16_SIZE;
        Ok(val)
    }

    pub fn read_u32(&mut self) -> Result<u32, DnsError> {
        if self.pos + U32_SIZE > self.buf.len() {
            return Err(DnsError::TooShort);
        }
        let val = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += U32_SIZE;
        Ok(val)
    }

    pub fn copy_to_slice(&mut self, dest: &mut [u8]) -> Result<(), DnsError> {
        if self.pos + dest.len() > self.buf.len() {
            return Err(DnsError::TooShort);
        }
        dest.copy_from_slice(&self.buf[self.pos..self.pos + dest.len()]);
        self.pos += dest.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_buffer_boundary_checks() {
        let data = [1, 2, 3];
        let mut buffer = PacketBuffer::new(&data);
        
        assert!(buffer.read_u32().is_err()); // Needs 4, only has 3
        buffer.pos = 2;
        assert!(buffer.read_u16().is_err()); // Needs 2, only has 1
    }

    #[test]
    fn test_packet_buffer_read_u32() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut buffer = PacketBuffer::new(&data);
        assert_eq!(buffer.read_u32().unwrap(), 0x12345678);
    }
}
