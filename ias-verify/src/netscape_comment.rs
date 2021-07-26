use crate::utils::{length_from_raw_data, safe_indexing};
use crate::{CertDer, IAS_SERVER_ROOTS, SUPPORTED_SIG_ALGS};
use frame_support::ensure;
use std::convert::TryFrom;

pub struct NetscapeComment<'a> {
    pub attestation_raw: &'a [u8],
    pub sig: Vec<u8>,
    pub sig_cert: Vec<u8>,
    pub entity_cert: Option<webpki::EndEntityCert<'a>>,
}

pub const NS_CMT_OID: &[u8; 11] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D,
];

impl<'a> TryFrom<CertDer<'a>> for NetscapeComment<'a> {
    type Error = &'static str;

    fn try_from(value: CertDer<'a>) -> Result<Self, Self::Error> {
        // Search for Netscape Comment OID
        let cert_der = value.0;

        let mut offset = cert_der
            .windows(NS_CMT_OID.len())
            .position(|window| window == NS_CMT_OID)
            .ok_or("Certificate does not contain 'ns_cmt_oid'")?;

        offset += 12; // 11 + TAG (0x04)

        #[cfg(test)]
        println!("netscape");
        // Obtain Netscape Comment length
        let len = length_from_raw_data(cert_der, &mut offset)?;
        // Obtain Netscape Comment
        offset += 1;
        let netscape_raw = safe_indexing(cert_der, offset, offset + len)?
            .split(|x| *x == 0x7C)
            .collect::<Vec<&[u8]>>();

        ensure!(netscape_raw.len() == 3, "Invalid netscape payload");

        let sig = base64::decode(netscape_raw[1]).map_err(|_| "Signature Decoding Error")?;

        let sig_cert = base64::decode_config(netscape_raw[2], base64::STANDARD)
            .map_err(|_| "Cert Decoding Error")?;

        Ok(NetscapeComment {
            attestation_raw: netscape_raw[0],
            sig: sig,
            sig_cert: sig_cert,
            entity_cert: None,
        })
    }
}

pub fn verify_signature(
    entity_cert: &webpki::EndEntityCert,
    attestation_raw: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    match entity_cert.verify_signature(
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        attestation_raw,
        signature,
    ) {
        Ok(()) => {
            #[cfg(test)]
            println!("IAS signature is valid");
            Ok(())
        }
        Err(_e) => {
            #[cfg(test)]
            println!("RSA Signature ERROR: {}", _e);
            Err("bad signature")
        }
    }
}

pub fn verify_server_cert(
    sig_cert: &webpki::EndEntityCert,
    timestamp_valid_until: webpki::Time,
) -> Result<(), &'static str> {
    let chain: Vec<&[u8]> = Vec::new();
    match sig_cert.verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS,
        &IAS_SERVER_ROOTS,
        &chain,
        timestamp_valid_until,
    ) {
        Ok(()) => {
            #[cfg(test)]
            println!("CA is valid");
            Ok(())
        }
        Err(_e) => {
            #[cfg(test)]
            println!("CA ERROR: {}", _e);
            Err("CA verification failed")
        }
    }
}
