use super::command::OpCode;
use super::error::{Error, ErrorKind, Status};
use crate::datalink::Transaction;
use core::convert::TryInto;
use core::mem::size_of;
use core::ops::RangeTo;
use crc::{Algorithm, Crc};

// Offset by word_address (1 byte)
const PACKET_OFFSET: usize = 1;
// PACKET_OFFSET + length (1 byte), opcode (1 byte), p1 (1 byte), p2 (2 bytes)
const PDU_OFFSET: usize = 6;
const CMD_SIZE_MIN: usize = 4;

/// Parameters to calculate CRC.
const CUSTOM_ALG: Algorithm<u16> = Algorithm {
    poly: 0x8005,
    init: 0x0000,
    refin: true,
    refout: false,
    xorout: 0x0000,
    check: 0xbcdd,
    residue: 0x0000,
};

/// CRC memoise table
const CRC16: Crc<u16> = Crc::<u16>::new(&CUSTOM_ALG);

pub struct PacketBuilder<'a> {
    buffer: &'a mut [u8],
    pdu_length: Option<usize>,
    opcode: Option<OpCode>,
    mode: Option<u8>,
    param2: Option<u16>,
}

impl<'a> PacketBuilder<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            pdu_length: None,
            opcode: None,
            mode: None,
            param2: None,
        }
    }

    pub fn opcode(&mut self, opcode: OpCode) -> &mut Self {
        self.opcode.replace(opcode);
        self
    }

    /// Mode parameter also referred as `param1`.
    pub fn mode(&mut self, mode: u8) -> &mut Self {
        self.mode.replace(mode);
        self
    }

    /// Key ID
    pub fn param2(&mut self, param2: u16) -> &mut Self {
        self.param2.replace(param2);
        self
    }

    pub fn pdu_data(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        self.buffer[PDU_OFFSET..]
            .as_mut()
            .copy_from_slice(data.as_ref());
        self.pdu_length.replace(data.as_ref().len());
        self
    }

    pub fn packet_buffer(&mut self) -> &mut [u8] {
        self.buffer[PACKET_OFFSET..].as_mut()
    }

    pub fn build(&mut self) -> Packet {
        let packet_length = self
            .pdu_length
            .iter()
            .fold(CMD_SIZE_MIN, |min, pdu_len| min + pdu_len);
        let opcode = self.opcode.expect("FIXME");
        let mode = self.mode.unwrap_or(0x00);
        let param2 = self.param2.unwrap_or(0x00);

        // Packet encoder is Hand-crafted. Any helpful library?
        self.buffer[0] = Transaction::Command as u8;
        let packet = self.packet_buffer();
        packet[0] = packet_length as u8;
        packet[1] = opcode as u8;
        packet[2] = mode;
        packet[3..5]
            .as_mut()
            .copy_from_slice(param2.to_le_bytes().as_ref());

        let crc_offset = packet_length - size_of::<u16>();
        let crc = CRC16.checksum(&packet[..crc_offset]);
        packet[crc_offset..packet_length]
            .as_mut()
            .copy_from_slice(crc.to_le_bytes().as_ref());
        Packet {
            range: (..packet_length + PACKET_OFFSET),
        }
    }
}

/// Assuming buffer is alocated elsewhere, `Packet` designates subslice in use.
pub struct Packet {
    range: RangeTo<usize>,
}

impl Packet {
    pub fn buffer(self, buffer: &[u8]) -> &[u8] {
        buffer[self.range].as_ref()
    }
}

pub struct Response<'a> {
    payload: &'a [u8],
}

impl<'a> Response<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        if buffer.len() < size_of::<u16>() {
            panic!("Buffer is too small.");
        }
        let (payload, crc_bytes) = buffer.split_at(buffer.len() - size_of::<u16>());
        let crc = u16::from_le_bytes(crc_bytes.try_into().unwrap_or_else(|_| unreachable!()));
        if crc == CRC16.checksum(&payload) {
            Ok(Self { payload: buffer })
        } else {
            Err(ErrorKind::RxCrcError.into())
        }
    }

    /// Check if the response indicates an error. The received data is expected
    /// to be in the form of a CA device response frame.
    pub fn error_status(&self) -> Result<(), Error> {
        // error packets are always 4 bytes long
        if (self.payload[0] == 0x04 && self.payload[1] != 0x00) {
            let status = Status::from_u8(self.payload[1]);
            return Err(status.into());
        }
        Ok(())
    }
}

impl<'a> AsRef<[u8]> for Response<'a> {
    fn as_ref(&self) -> &[u8] {
        self.payload
    }
}
