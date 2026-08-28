//! Error-control checksum (PI 1 "utilisation d'un CRC", §4.3.2.3): the ISO 8073 (transport
//! class 4) Fletcher checksum computed modulo 255 over the whole FPDU, with the two check bytes
//! placed at the end of the FPDU. The two bytes are not counted in the FPDU length field.
//! Algorithm validated for interoperability with Connect:Express.

/// Number of check bytes appended to a FPDU when the CRC option is negotiated.
pub const CRC_LEN: usize = 2;

/// Compute the two check bytes for `fpdu` (the FPDU bytes without check bytes).
#[must_use]
pub fn compute(fpdu: &[u8]) -> [u8; 2] {
    let (s1, s2) = sums(fpdu.iter().copied().chain([0u8, 0u8]));
    // x = C0 - C1 ; y = C1 - 2*C0 (mod 255), check bytes positioned at the end of the message.
    let x = (s1 + 255 - s2) % 255;
    let y = (s2 + 2 * (255 - s1)) % 255;
    [x as u8, y as u8]
}

/// Verify a FPDU followed by its two check bytes.
#[must_use]
pub fn verify(fpdu_with_crc: &[u8]) -> bool {
    if fpdu_with_crc.len() < CRC_LEN {
        return false;
    }
    let (s1, s2) = sums(fpdu_with_crc.iter().copied());
    s1 == 0 && s2 == 0
}

/// Append the check bytes to `fpdu` in place.
pub fn append(fpdu: &mut Vec<u8>) {
    let c = compute(fpdu);
    fpdu.extend_from_slice(&c);
}

fn sums(bytes: impl Iterator<Item = u8>) -> (u32, u32) {
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;
    for b in bytes {
        s1 = (s1 + u32::from(b)) % 255;
        s2 = (s2 + s1) % 255;
    }
    (s1, s2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for msg in [
            &b""[..],
            b"\x00\x06\xc0\x02\x05\x00",
            b"\x00\x2f\x40\x20\x00\x01\x03\x08CXCLIENT\x04\x08PESITSRV\x06\x01\x02\x16\x01\x00",
            &[0xffu8; 300][..],
        ] {
            let mut v = msg.to_vec();
            append(&mut v);
            assert!(verify(&v), "{msg:?}");
            v[0] ^= 1;
            assert!(!verify(&v));
        }
    }

    #[test]
    fn matches_connect_express_algorithm() {
        // Reference vector for interoperability cross-checking.
        fn cx(msg: &[u8]) -> [u8; 2] {
            let mut buf = msg.to_vec();
            buf.extend_from_slice(&[0, 0]);
            let (mut s1, mut s2) = (0u16, 0u16);
            for &b in &buf {
                s1 += u16::from(b);
                if s1 > 0xFE {
                    s1 -= 0xFF;
                }
                s2 += s1;
                if s2 > 0xFE {
                    s2 -= 0xFF;
                }
            }
            s1 %= 255;
            s2 %= 255;
            let c0 = if s1 >= s2 {
                (s1 - s2) as u8
            } else {
                (s1.wrapping_sub(s2) as u8).wrapping_sub(1)
            };
            let s1b = (2 * s1) % 255;
            let c1 = if s2 >= s1b {
                (s2 - s1b) as u8
            } else {
                (s2.wrapping_sub(s1b) as u8).wrapping_sub(1)
            };
            [c0, c1]
        }
        for msg in [
            &b"hello world"[..],
            b"\x00\x0e\x00\x0e\x40\x21\x62\xe2\x06\x01\x02\x07\x03\x00\x20\x02",
            &[0xfe; 17][..],
        ] {
            assert_eq!(compute(msg), cx(msg));
        }
    }
}
