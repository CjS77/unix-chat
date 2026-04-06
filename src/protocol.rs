use std::io::{Read, Write};

use crate::error::{ChatError, Result};

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB

/// Write a length-prefixed message to the stream.
/// Format: [4 bytes BE u32 length][payload]
pub fn write_message(stream: &mut impl Write, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Read a length-prefixed message from the stream.
/// Returns None on clean EOF (connection closed), Err on protocol violations.
pub fn read_message(stream: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(ChatError::Crypto(format!("Message too large: {len} bytes (max {MAX_MESSAGE_SIZE})")));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_read_round_trip() {
        let payload = b"hello, encrypted world!";
        let mut buf = Vec::new();
        write_message(&mut buf, payload).unwrap();

        let mut cursor = Cursor::new(buf);
        let result = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn read_empty_stream_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn multiple_messages() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"first").unwrap();
        write_message(&mut buf, b"second").unwrap();
        write_message(&mut buf, b"third").unwrap();

        let mut cursor = Cursor::new(buf);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), b"first");
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), b"second");
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), b"third");
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_message() {
        let len = (MAX_MESSAGE_SIZE + 1).to_be_bytes();
        let mut cursor = Cursor::new(len.to_vec());
        assert!(read_message(&mut cursor).is_err());
    }
}
