use bytes::{BufMut, BytesMut};
use crate::protocol::buffer::PacketBuffer;
use crate::protocol::{DnsError, MAX_JUMPS, COMPRESSION_MASK};

pub fn encode_name(name: &str, buf: &mut BytesMut) {
    for label in name.split('.') {
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0);
}

pub fn decode_name(buffer: &mut PacketBuffer) -> Result<String, DnsError> {
    decode_name_recursive(buffer, 0)
}

fn decode_name_recursive(buffer: &mut PacketBuffer, jumps: u8) -> Result<String, DnsError> {
    if jumps > MAX_JUMPS {
        return Err(DnsError::TooManyJumps);
    }

    let mut name = String::new();

    loop {
        let len = buffer.read_u8()?;
        
        // 1. Check for compression (top two bits set: 0b11000000)
        if (len & COMPRESSION_MASK) == COMPRESSION_MASK {
            let b2 = buffer.read_u8()?;
            let offset = (((len as u16) ^ (COMPRESSION_MASK as u16)) << 8) | (b2 as u16);
            
            // In a recursive jump, we resolve the suffix and join it
            let mut temp_buffer = PacketBuffer {
                buf: buffer.buf,
                pos: offset as usize,
            };
            
            let suffix = decode_name_recursive(&mut temp_buffer, jumps + 1)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&suffix);
            
            // Once we jump, the name is finished
            return Ok(name);
        }

        // 2. Normal label
        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        // Boundary check before reading label
        if buffer.pos + len as usize > buffer.buf.len() {
            return Err(DnsError::TooShort);
        }

        let mut label_bytes = vec![0; len as usize];
        buffer.copy_to_slice(&mut label_bytes)?;
        name.push_str(&String::from_utf8(label_bytes)?);
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_label() {
        // Label says length is 10, but only 3 bytes follow before null
        let data = [10, b'a', b'b', b'c', 0];
        let mut packet_buffer = PacketBuffer::new(&data);
        let result = decode_name(&mut packet_buffer);
        assert!(matches!(result, Err(DnsError::TooShort)));
    }

    #[test]
    fn test_decompression() {
        // Packet:
        // [0..12] Header
        // [12..24] "google.com" (length 6 + google + length 3 + com + 0)
        // [24] Pointer to offset 12 (0xC0, 0x0C)
        let mut data = vec![0u8; 12]; // Dummy header
        data.extend_from_slice(&[6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        data.extend_from_slice(&[0xC0, 12]);

        let mut packet_buffer = PacketBuffer::new(&data);
        packet_buffer.pos = 24; // Seek to the pointer

        let name = decode_name(&mut packet_buffer).expect("Should decode compressed name");
        assert_eq!(name, "google.com");
    }

    #[test]
    fn test_infinite_compression_loop() {
        // Offset 0: 0xC0, 0x00 (Points to itself)
        let data = [0xC0, 0x00];
        let mut buffer = PacketBuffer::new(&data);
        let result = decode_name(&mut buffer);
        
        assert!(matches!(result, Err(DnsError::TooManyJumps)));
    }

    #[test]
    fn test_nested_decompression() {
        // [0..11] "google.com"
        // [11.. ] "news." + pointer to 0
        let mut data = vec![6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0];
        data.extend_from_slice(&[4, b'n', b'e', b'w', b's', 0xC0, 0]);

        let mut buffer = PacketBuffer::new(&data);
        buffer.pos = 12; // Start at "news"

        let name = decode_name(&mut buffer).unwrap();
        assert_eq!(name, "news.google.com");
    }

    #[test]
    fn test_jump_limit_edge_case() {
        // Test exactly 5 jumps (should pass) and 6 jumps (should fail)
        let mut data = vec![0u8; 100];
        // 0->2, 2->4, 4->6, 6->8, 8->10, 10-> "end"
        data[0..2].copy_from_slice(&[0xC0, 2]);
        data[2..4].copy_from_slice(&[0xC0, 4]);
        data[4..6].copy_from_slice(&[0xC0, 6]);
        data[6..8].copy_from_slice(&[0xC0, 8]);
        data[8..10].copy_from_slice(&[0xC0, 10]);
        data[10..15].copy_from_slice(&[3, b'e', b'n', b'd', 0]);

        let mut buffer = PacketBuffer::new(&data);
        assert!(decode_name(&mut buffer).is_ok());

        // Now 6 jumps: 0->2->4->6->8->10->12-> "end"
        let mut data6 = vec![0u8; 100];
        data6[0..2].copy_from_slice(&[0xC0, 2]);
        data6[2..4].copy_from_slice(&[0xC0, 4]);
        data6[4..6].copy_from_slice(&[0xC0, 6]);
        data6[6..8].copy_from_slice(&[0xC0, 8]);
        data6[8..10].copy_from_slice(&[0xC0, 10]);
        data6[10..12].copy_from_slice(&[0xC0, 12]);
        data6[12..17].copy_from_slice(&[3, b'e', b'n', b'd', 0]);

        let mut buffer6 = PacketBuffer::new(&data6);
        assert!(matches!(decode_name(&mut buffer6), Err(DnsError::TooManyJumps)));
    }
}
