use crate::utils::{length_from_raw_data, safe_indexing};
use crate::CertDer;
use std::convert::TryFrom;

pub struct PubKey<'a>(&'a [u8]);

pub const PRIME256V1_OID: &[u8; 10] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
impl<'a> TryFrom<CertDer<'a>> for PubKey<'a> {
    type Error = &'static str;

    fn try_from(value: CertDer<'a>) -> Result<Self, Self::Error> {
        let cert_der = value.0;

        let mut offset = cert_der
            .windows(PRIME256V1_OID.len())
            .position(|window| window == PRIME256V1_OID)
            .ok_or("Certificate does not contain 'PRIME256V1_OID'")?;

        offset += 11; // 10 + TAG (0x03)

        // Obtain Public Key length
        let mut len = length_from_raw_data(cert_der, &mut offset)?;

        // Obtain Public Key
        offset += 1;
        let _pub_k = safe_indexing(cert_der, offset + 2, offset + len)?; // skip "00 04"

        #[cfg(test)]
        println!("verifyRA ephemeral public key: {:x?}", _pub_k);
        Ok(PubKey(_pub_k))
    }
}
