use super::command::OpCode;
use super::error::{Error, ErrorKind, Status};
use crate::datalink::Transaction;
use core::convert::{TryFrom, TryInto};
use core::mem::size_of;
use core::ops::RangeTo;
use crc::{Algorithm, Crc};

// Offset by word_address (1 byte)
const PACKET_OFFSET: usize = 1;
// PACKET_OFFSET + length (1 byte), opcode (1 byte), p1 (1 byte), p2 (2 bytes)
const PDU_OFFSET: usize = 6;
// Length (1 byte), opcode (1 byte), p1 (1 byte), p2 (2 bytes), crc (2 bytes)
const CMD_SIZE_MIN: usize = 7;

// Parameters to calculate CRC.
const CUSTOM_ALG: Algorithm<u16> = Algorithm {
    width: 16,
    poly: 0x8005,
    init: 0x0000,
    refin: true,
    refout: false,
    xorout: 0x0000,
    check: 0xbcdd,
    residue: 0x0000,
};

// CRC memoise table
pub const CRC16: Crc<u16> = Crc::<u16>::new(&CUSTOM_ALG);

#[derive(Debug)]
pub(crate) struct PacketBuilder<'a> {
    buffer: &'a mut [u8],
    pdu_length: Option<usize>,
    opcode: Option<OpCode>,
    mode: Option<u8>,
    param2: Option<u16>,
}

impl<'a> PacketBuilder<'a> {
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            pdu_length: None,
            opcode: None,
            mode: None,
            param2: None,
        }
    }

    pub(crate) fn opcode(&mut self, opcode: OpCode) -> &mut Self {
        self.opcode.replace(opcode);
        self
    }

    /// Mode parameter also referred as `param1`.
    pub(crate) fn mode(&mut self, mode: u8) -> &mut Self {
        self.mode.replace(mode);
        self
    }

    /// Key ID
    pub(crate) fn param2(&mut self, param2: u16) -> &mut Self {
        self.param2.replace(param2);
        self
    }

    pub(crate) fn pdu_data(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        let data_length = data.as_ref().len();
        self.buffer[PDU_OFFSET..PDU_OFFSET + data_length]
            .as_mut()
            .copy_from_slice(data.as_ref());
        self.pdu_length.replace(data_length);
        self
    }

    // Input length cannot exceed the length of underlying buffer. Only use it
    // for packets of fixed length. Also note that `pdu_data` modifies `pdu_length`.
    pub(crate) fn pdu_length(&mut self, length: usize) -> &mut Self {
        self.pdu_length.replace(length);
        self
    }

    pub(crate) fn packet_buffer(&mut self) -> &mut [u8] {
        self.buffer[PACKET_OFFSET..].as_mut()
    }

    pub(crate) fn pdu_buffer(&mut self) -> &mut [u8] {
        self.buffer[PDU_OFFSET..].as_mut()
    }

    pub(crate) fn build(&mut self) -> Result<Packet, Error> {
        let packet_length = self
            .pdu_length
            .iter()
            .fold(CMD_SIZE_MIN, |min, pdu_len| min + pdu_len);
        let opcode = self.opcode.ok_or(Error::from(ErrorKind::BadOpcode))?;
        let mode = self.mode.unwrap_or_default();
        let param2 = self.param2.unwrap_or_default();

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
        Ok(Packet {
            opcode,
            range: (..packet_length + PACKET_OFFSET),
        })
    }
}

impl<'a> From<&'a mut [u8]> for PacketBuilder<'a> {
    fn from(buffer: &'a mut [u8]) -> Self {
        Self::new(buffer)
    }
}

/// Assuming buffer is alocated elsewhere, `Packet` designates subslice in use.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Packet {
    opcode: OpCode,
    range: RangeTo<usize>,
}

impl Packet {
    pub(crate) fn opcode(&self) -> &OpCode {
        &self.opcode
    }

    pub(crate) fn buffer(self, buffer: &[u8]) -> &[u8] {
        buffer[self.range].as_ref()
    }
}

// Is it possible to classify the response into [] | [u8; WORD] | [u8; BLOCK]?
// TODO: Testing purpose only. Should not be public.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    pdu: &'a [u8],
}

impl<'a> Response<'a> {
    /// Check if the response indicates an error. The received data is expected
    /// to be in the form of a CA device response frame.
    /// Extract PDU.
    pub(crate) fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        // Check if buffer is well-formed.
        if buffer.len() < 0x04 {
            // Buffer is too small. Bail out.
            return Err(ErrorKind::RxFail.into());
        }

        // Check CRC.
        let (payload, crc_bytes) = buffer.split_at(buffer.len() - size_of::<u16>());
        let crc = crc_bytes
            .try_into()
            .map(u16::from_le_bytes)
            .unwrap_or_else(|_| unreachable!());
        if crc != CRC16.checksum(&payload) {
            return Err(ErrorKind::RxCrcError.into());
        }

        // Check error status. Error packets are always 4 bytes long.
        let (header, pdu) = payload.split_at(1);
        if header[0] == 0x04 {
            if let Ok(status) = Status::try_from(pdu[0]) {
                return Err(status.into());
            }
        }

        Ok(Self { pdu })
    }
}

impl<'a> AsRef<[u8]> for Response<'a> {
    fn as_ref(&self) -> &[u8] {
        self.pdu
    }
}
