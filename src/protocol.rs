use std::io::{Read, Write};

use crate::error::{ChatError, Result};

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB

/// Typed message discriminator. The relay forwards this opaquely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Text,
    File,
    Unknown(u16),
}

impl MessageType {
    pub fn to_u16(self) -> u16 {
        match self {
            MessageType::Text => 0x0001,
            MessageType::File => 0x0002,
            MessageType::Unknown(v) => v,
        }
    }
}

impl From<u16> for MessageType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => MessageType::Text,
            0x0002 => MessageType::File,
            _ => MessageType::Unknown(v),
        }
    }
}

/// Write a typed, length-prefixed message to the stream.
/// Format: [2 bytes BE u16 type][4 bytes BE u32 length][payload]
pub fn write_message(stream: &mut impl Write, msg_type: MessageType, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_MESSAGE_SIZE as usize {
        return Err(ChatError::Crypto(format!(
            "Message too large to send: {} bytes (max {MAX_MESSAGE_SIZE})",
            payload.len()
        )));
    }
    let len = payload.len() as u32;
    stream.write_all(&msg_type.to_u16().to_be_bytes())?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Read a typed, length-prefixed message from the stream.
/// Returns None on clean EOF (connection closed), Err on protocol violations.
pub fn read_message(stream: &mut impl Read) -> Result<Option<(MessageType, Vec<u8>)>> {
    let mut type_buf = [0u8; 2];
    match stream.read_exact(&mut type_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let msg_type = MessageType::from(u16::from_be_bytes(type_buf));

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(ChatError::Crypto(format!(
            "Message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"
        )));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(Some((msg_type, buf)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_read_round_trip() {
        let payload = b"hello, encrypted world!";
        let mut buf = Vec::new();
        write_message(&mut buf, MessageType::Text, payload).unwrap();

        let mut cursor = Cursor::new(buf);
        let (msg_type, result) = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(msg_type, MessageType::Text);
        assert_eq!(result, payload);
    }

    #[test]
    fn write_read_file_type() {
        let payload = b"file-contents";
        let mut buf = Vec::new();
        write_message(&mut buf, MessageType::File, payload).unwrap();

        let mut cursor = Cursor::new(buf);
        let (msg_type, result) = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(msg_type, MessageType::File);
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
        write_message(&mut buf, MessageType::Text, b"first").unwrap();
        write_message(&mut buf, MessageType::File, b"second").unwrap();
        write_message(&mut buf, MessageType::Text, b"third").unwrap();

        let mut cursor = Cursor::new(buf);
        let (t, d) = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!((t, d.as_slice()), (MessageType::Text, b"first".as_slice()));
        let (t, d) = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!((t, d.as_slice()), (MessageType::File, b"second".as_slice()));
        let (t, d) = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!((t, d.as_slice()), (MessageType::Text, b"third".as_slice()));
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_message() {
        let mut data = Vec::new();
        data.extend_from_slice(&MessageType::Text.to_u16().to_be_bytes());
        data.extend_from_slice(&(MAX_MESSAGE_SIZE + 1).to_be_bytes());
        let mut cursor = Cursor::new(data);
        assert!(read_message(&mut cursor).is_err());
    }

    #[test]
    fn unknown_type_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, MessageType::Unknown(0xFFFF), b"future").unwrap();

        let mut cursor = Cursor::new(buf);
        let (msg_type, result) = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(msg_type, MessageType::Unknown(0xFFFF));
        assert_eq!(result, b"future");
    }
}
