/*
    Copyright 2019 Supercomputing Systems AG

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

*/

#![cfg_attr(not(feature = "std"), no_std)]

use chrono::prelude::*;
use sp_std::convert::TryInto;
use sp_std::prelude::*;
//use itertools::Itertools;
//use log::*;
//use serde_json::Value;
//use sgx_types::*;
//use sgx_ucrypto::SgxEccHandle;

//use super::{SgxReport, SgxStatus};
use codec::{Decode, Encode};
use serde_json::Value;

const SGX_REPORT_DATA_SIZE: usize = 64;
#[derive(Encode, Decode, Copy, Clone)]
pub struct SgxReportData {
    d: [u8; SGX_REPORT_DATA_SIZE],
}

// see Intel SGX SDK https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_report.h
const SGX_REPORT_BODY_RESERVED1_BYTES: usize = 12;
const SGX_REPORT_BODY_RESERVED2_BYTES: usize = 32;
const SGX_REPORT_BODY_RESERVED3_BYTES: usize = 32;
const SGX_REPORT_BODY_RESERVED4_BYTES: usize = 42;

#[derive(Encode, Decode, Copy, Clone)]
pub struct SgxReportBody {
    cpu_svn: [u8; 16],    /* (  0) Security Version of the CPU */
    misc_select: [u8; 4], /* ( 16) Which fields defined in SSA.MISC */
    reserved1: [u8; SGX_REPORT_BODY_RESERVED1_BYTES], /* ( 20) */
    isv_ext_prod_id: [u8; 16], /* ( 32) ISV assigned Extended Product ID */
    attributes: [u8; 16], /* ( 48) Any special Capabilities the Enclave possess */
    mr_enclave: [u8; 32], /* ( 64) The value of the enclave's ENCLAVE measurement */
    reserved2: [u8; SGX_REPORT_BODY_RESERVED2_BYTES], /* ( 96) */
    mr_signer: [u8; 32],  /* (128) The value of the enclave's SIGNER measurement */
    reserved3: [u8; SGX_REPORT_BODY_RESERVED3_BYTES], /* (160) */
    config_id: [u8; 64],  /* (192) CONFIGID */
    isv_prod_id: u16,     /* (256) Product ID of the Enclave */
    isv_svn: u16,         /* (258) Security Version of the Enclave */
    config_svn: u16,      /* (260) CONFIGSVN */
    reserved4: [u8; SGX_REPORT_BODY_RESERVED4_BYTES], /* (262) */
    isv_family_id: [u8; 16], /* (304) ISV assigned Family ID */
    report_data: SgxReportData, /* (320) Data provided by the user */
}

// see Intel SGX SDK https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_quote.h
#[derive(Encode, Decode, Copy, Clone)]
pub struct SgxQuote {
    version: u16,       /* 0   */
    sign_type: u16,     /* 2   */
    epid_group_id: u32, /* 4   */
    qe_svn: u16,        /* 8   */
    pce_svn: u16,       /* 10  */
    xeid: u32,          /* 12  */
    basename: [u8; 32], /* 16  */
    report_body: SgxReportBody, /* 48  */
                        //signature_len: u32,    /* 432 */
                        //signature: [u8; 64]    /* 436 */  //must be hard-coded for SCALE codec
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, sp_core::RuntimeDebug)]
pub enum SgxStatus {
    Invalid,
    Ok,
    GroupOutOfDate,
    GroupRevoked,
    ConfigurationNeeded,
}
impl Default for SgxStatus {
    fn default() -> Self {
        SgxStatus::Invalid
    }
}

#[derive(Encode, Decode, Default, Copy, Clone, PartialEq, sp_core::RuntimeDebug)]
pub struct SgxReport {
    pub mr_enclave: [u8; 32],
    pub pubkey: [u8; 32],
    pub status: SgxStatus,
    pub timestamp: u64,
}

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    //&webpki::ECDSA_P256_SHA256,
    //&webpki::ECDSA_P256_SHA384,
    //&webpki::ECDSA_P384_SHA256,
    //&webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

//pub const IAS_REPORT_CA: &[u8] = include_bytes!("../AttestationReportSigningCACert.pem");

pub static IAS_SERVER_ROOTS: webpki::TLSServerTrustAnchors = webpki::TLSServerTrustAnchors(&[
	/*
	 * -----BEGIN CERTIFICATE-----
	 * MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
	 * BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
	 * BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
	 * YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
	 * MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
	 * U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
	 * DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
	 * CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
	 * LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
	 * rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
	 * L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
	 * NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
	 * byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
	 * afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
	 * 6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
	 * RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
	 * MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
	 * L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
	 * BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
	 * NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
	 * hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
	 * IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
	 * sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
	 * zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
	 * Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
	 * 152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
	 * 3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
	 * DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
	 * DaVzWh5aiEx+idkSGMnX
	 * -----END CERTIFICATE-----
	 */
	webpki::TrustAnchor {
		subject: b"1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0b0\t\x06\x03U\x04\x08\x0c\x02CA1\x140\x12\x06\x03U\x04\x07\x0c\x0bSanta Clara1\x1a0\x18\x06\x03U\x04\n\x0c\x11Intel Corporation100.\x06\x03U\x04\x03\x0c\'Intel SGX Attestation Report Signing CA",
		spki: b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x8f\x000\x82\x01\x8a\x02\x82\x01\x81\x00\x9f<d~\xb5w<\xbbQ-\'2\xc0\xd7A^\xbbU\xa0\xfa\x9e\xde.d\x91\x99\xe6\x82\x1d\xb9\x10\xd51w7\twFjj^G\x86\xcc\xd2\xdd\xeb\xd4\x14\x9dj/c%R\x9d\xd1\x0c\xc9\x877\xb0w\x9c\x1a\x07\xe2\x9cG\xa1\xae\x00IHGlH\x9fE\xa5\xa1]z\xc8\xec\xc6\xac\xc6E\xad\xb4=\x87g\x9d\xf5\x9c\t;\xc5\xa2\xe9ilTxT\x1b\x97\x9euKW9\x14\xbeU\xd3/\xf4\xc0\x9d\xdf\'!\x994\xcd\x99\x05\'\xb3\xf9.\xd7\x8f\xbf)$j\xbe\xcbq$\x0e\xf3\x9c-q\x07\xb4GTZ\x7f\xfb\x10\xeb\x06\nh\xa9\x85\x80!\x9e6\x91\tRh8\x92\xd6\xa5\xe2\xa8\x08\x03\x19>@u1@N6\xb3\x15b7\x99\xaa\x82Pt@\x97T\xa2\xdf\xe8\xf5\xaf\xd5\xfec\x1e\x1f\xc2\xaf8\x08\x90o(\xa7\x90\xd9\xdd\x9f\xe0`\x93\x9b\x12W\x90\xc5\x80]\x03}\xf5j\x99S\x1b\x96\xdei\xde3\xed\"l\xc1 }\x10B\xb5\xc9\xab\x7f@O\xc7\x11\xc0\xfeGi\xfb\x95x\xb1\xdc\x0e\xc4i\xea\x1a%\xe0\xff\x99\x14\x88n\xf2i\x9b#[\xb4\x84}\xd6\xff@\xb6\x06\xe6\x17\x07\x93\xc2\xfb\x98\xb3\x14X\x7f\x9c\xfd%sb\xdf\xea\xb1\x0b;\xd2\xd9vs\xa1\xa4\xbdD\xc4S\xaa\xf4\x7f\xc1\xf2\xd3\xd0\xf3\x84\xf7J\x06\xf8\x9c\x08\x9f\r\xa6\xcd\xb7\xfc\xee\xe8\xc9\x82\x1a\x8eT\xf2\\\x04\x16\xd1\x8cF\x83\x9a_\x80\x12\xfb\xdd=\xc7M%by\xad\xc2\xc0\xd5Z\xffo\x06\"B]\x1b\x02\x03\x01\x00\x01",
		name_constraints: None
	},

]);

// prevents panics in case of index out of bounds
fn safe_indexing(data: &[u8], start: usize, end: usize) -> Result<&[u8], &'static str> {
    if start > end {
        return Err("Illegal indexing");
    }
    if data.len() < end {
        return Err("Index would be out of bounds");
    }
    Ok(&data[start..end])
}
fn safe_indexing_one(data: &[u8], idx: usize) -> Result<u8, &'static str> {
    if data.len() < idx {
        return Err("Index would be out of bounds");
    }
    Ok(data[idx])
}

// make sure this function doesn't panic!
pub fn verify_ias_report(cert_der: &[u8]) -> Result<SgxReport, &'static str> {
    #[cfg(test)]
    println!("verifyRA: start verifying RA cert");
    // Before we reach here, the runtime already verifed the extrinsic is properly signed by the extrinsic sender
    // Search for Public Key prime256v1 OID
    let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let mut offset = match cert_der
        .windows(prime256v1_oid.len())
        .position(|window| window == prime256v1_oid)
    {
        Some(o) => o,
        _ => return Err("Certificate to check is empty"),
    };
    offset += 11; // 10 + TAG (0x03)

    // Obtain Public Key length
    let mut len = safe_indexing_one(cert_der, offset)? as usize;
    if len > 0x80 {
        len = (safe_indexing_one(cert_der, offset + 1)? as usize) * 0x100
            + (safe_indexing_one(cert_der, offset + 2)? as usize);
        offset += 2;
    }

    // Obtain Public Key
    offset += 1;
    let _pub_k = safe_indexing(cert_der, offset + 2, offset + len)?.to_vec(); // skip "00 04"

    #[cfg(test)]
    println!("verifyRA ephemeral public key: {:x?}", _pub_k);

    // Search for Netscape Comment OID
    let ns_cmt_oid = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D,
    ];
    let mut offset = match cert_der
        .windows(ns_cmt_oid.len())
        .position(|window| window == ns_cmt_oid)
    {
        Some(o) => o,
        _ => return Err("Certificate to check is empty"),
    };
    offset += 12; // 11 + TAG (0x04)

    #[cfg(test)]
    println!("netscape");
    // Obtain Netscape Comment length
    let mut len = safe_indexing_one(cert_der, offset)? as usize;

    if len > 0x80 {
        len = (safe_indexing_one(cert_der, offset + 1)? as usize) * 0x100
            + (safe_indexing_one(cert_der, offset + 2)? as usize);
        offset += 2;
    }

    // Obtain Netscape Comment
    offset += 1;
    let payload = safe_indexing(cert_der, offset, offset + len)?.to_vec();

    // Extract each field
    let mut iter = payload.split(|x| *x == 0x7C);
    let attn_report_raw = iter.next().unwrap();
    let sig_raw = iter.next().unwrap();
    let sig = match base64::decode(&sig_raw) {
        Ok(m) => m,
        Err(_) => return Err("Signature Decoding Error"),
    };

    let sig_cert_raw = iter.next().unwrap();
    let sig_cert_dec = match base64::decode_config(&sig_cert_raw, base64::STANDARD) {
        Ok(c) => c,
        Err(_) => return Err("Cert Decoding Error"),
    };
    let sig_cert = match webpki::EndEntityCert::from(&sig_cert_dec) {
        Ok(c) => c,
        Err(_) => return Err("Bad DER"),
    };

    let chain: Vec<&[u8]> = Vec::new();
    // FIXME: now hardcoded. but certificate renewal would have to be done manually anyway...
    // chain wasm update or by some sudo call
    let now_func = webpki::Time::from_seconds_since_unix_epoch(1573419050);

    match sig_cert.verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS,
        &IAS_SERVER_ROOTS,
        &chain,
        now_func,
    ) {
        Ok(()) => {
            #[cfg(test)]
            println!("CA is valid");
        }
        Err(_e) => {
            #[cfg(test)]
            println!("CA ERROR: {}", _e);
            return Err("CA verification failed");
        }
    };

    match sig_cert.verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, &attn_report_raw, &sig) {
        Ok(()) => {
            #[cfg(test)]
            println!("IAS signature is valid");
        }
        Err(_e) => {
            #[cfg(test)]
            println!("RSA Signature ERROR: {}", _e);
            return Err("bad signature");
        }
    }

    parse_report(attn_report_raw)
}

fn parse_report(report_raw: &[u8]) -> Result<SgxReport, &'static str> {
    // parse attestation report
    let attn_report: Value = match serde_json::from_slice(report_raw) {
        Ok(report) => report,
        Err(_) => return Err("RA report parsing error"),
    };

    let _ra_timestamp = match &attn_report["timestamp"] {
        Value::String(time) => {
            let time_fixed = time.clone() + "+0000";
            match DateTime::parse_from_str(&time_fixed, "%Y-%m-%dT%H:%M:%S%.f%z") {
                Ok(d) => d.timestamp(),
                Err(_) => return Err("RA report timestamp parsing error"),
            }
        }
        _ => return Err("Failed to fetch timestamp from attestation report"),
    };

    let ra_timestamp: u64 = _ra_timestamp
        .try_into()
        .map_err(|_| "Error converting report.timestamp to u64")?;

    #[cfg(test)]
    println!(
        "verifyRA attestation timestamp [unix epoch]: {}",
        ra_timestamp
    );

    // get quote status (mandatory field)
    let ra_status = match &attn_report["isvEnclaveQuoteStatus"] {
        Value::String(quote_status) => match quote_status.as_ref() {
            "OK" => SgxStatus::Ok,
            "GROUP_OUT_OF_DATE" => SgxStatus::GroupOutOfDate,
            "GROUP_REVOKED" => SgxStatus::GroupRevoked,
            "CONFIGURATION_NEEDED" => SgxStatus::ConfigurationNeeded,
            _ => SgxStatus::Invalid,
        },
        _ => return Err("Failed to fetch isvEnclaveQuoteStatus from attestation report"),
    };

    #[cfg(test)]
    println!("verifyRA attestation status is: {:?}", ra_status);
    // parse quote body
    if let Value::String(quote_raw) = &attn_report["isvEnclaveQuoteBody"] {
        let quote = match base64::decode(&quote_raw) {
            Ok(q) => q,
            Err(_) => return Err("Quote Decoding Error"),
        };
        #[cfg(test)]
        println!("Quote read. len={}", quote.len());
        // TODO: lack security check here
        let sgx_quote: SgxQuote = match Decode::decode(&mut &quote[..]) {
            Ok(q) => q,
            Err(_) => return Err("could not decode quote"),
        };

        #[cfg(test)]
        {
            println!("sgx quote version = {}", sgx_quote.version);
            println!("sgx quote signature type = {}", sgx_quote.sign_type);
            //println!("sgx quote report_data = {:?}", sgx_quote.report_body.report_data.d[..32]);
            println!(
                "sgx quote mr_enclave = {:x?}",
                sgx_quote.report_body.mr_enclave
            );
            println!(
                "sgx quote mr_signer = {:x?}",
                sgx_quote.report_body.mr_signer
            );
            println!(
                "sgx quote report_data = {:x?}",
                sgx_quote.report_body.report_data.d.to_vec()
            );
        }

        let mut xt_signer_array = [0u8; 32];
        xt_signer_array.copy_from_slice(&sgx_quote.report_body.report_data.d[..32]);
        Ok(SgxReport {
            mr_enclave: sgx_quote.report_body.mr_enclave,
            status: ra_status,
            pubkey: xt_signer_array,
            timestamp: ra_timestamp,
        })
    } else {
        Err("Failed to parse isvEnclaveQuoteBody from attestation report")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Decode;
    use hex_literal::hex;
    // reproduce with "substratee_worker dump_ra"
    const TEST1_CERT: &[u8] = include_bytes!("../test/test_ra_cert_MRSIGNER1_MRENCLAVE1.der");
    const TEST2_CERT: &[u8] = include_bytes!("../test/test_ra_cert_MRSIGNER2_MRENCLAVE2.der");
    const TEST3_CERT: &[u8] = include_bytes!("../test/test_ra_cert_MRSIGNER3_MRENCLAVE2.der");
    const TEST4_CERT: &[u8] = include_bytes!("../test/ra_dump_cert_TEST4.der");
    const TEST5_CERT: &[u8] = include_bytes!("../test/ra_dump_cert_TEST5.der");
    const TEST6_CERT: &[u8] = include_bytes!("../test/ra_dump_cert_TEST6.der");
    const TEST7_CERT: &[u8] = include_bytes!("../test/ra_dump_cert_TEST7.der");

    const TEST1_SIGNER_ATTN: &[u8] =
        include_bytes!("../test/test_ra_signer_attn_MRSIGNER1_MRENCLAVE1.bin");
    const TEST2_SIGNER_ATTN: &[u8] =
        include_bytes!("../test/test_ra_signer_attn_MRSIGNER2_MRENCLAVE2.bin");
    const TEST3_SIGNER_ATTN: &[u8] =
        include_bytes!("../test/test_ra_signer_attn_MRSIGNER3_MRENCLAVE2.bin");

    // reproduce with "substratee_worker signing-key"
    const TEST1_SIGNER_PUB: &[u8] =
        include_bytes!("../test/test_ra_signer_pubkey_MRSIGNER1_MRENCLAVE1.bin");
    const TEST2_SIGNER_PUB: &[u8] =
        include_bytes!("../test/test_ra_signer_pubkey_MRSIGNER2_MRENCLAVE2.bin");
    const TEST3_SIGNER_PUB: &[u8] =
        include_bytes!("../test/test_ra_signer_pubkey_MRSIGNER3_MRENCLAVE2.bin");
    const TEST4_SIGNER_PUB: &[u8] = include_bytes!("../test/enclave-signing-pubkey-TEST4.bin");
    // equal to TEST4!
    const TEST5_SIGNER_PUB: &[u8] = include_bytes!("../test/enclave-signing-pubkey-TEST5.bin");
    const TEST6_SIGNER_PUB: &[u8] = include_bytes!("../test/enclave-signing-pubkey-TEST6.bin");
    const TEST7_SIGNER_PUB: &[u8] = include_bytes!("../test/enclave-signing-pubkey-TEST7.bin");

    // reproduce with "make mrenclave" in worker repo root
    const TEST1_MRENCLAVE: &[u8] = &[
        62, 252, 187, 232, 60, 135, 108, 204, 87, 78, 35, 169, 241, 237, 106, 217, 251, 241, 99,
        189, 138, 157, 86, 136, 77, 91, 93, 23, 192, 104, 140, 167,
    ];
    const TEST2_MRENCLAVE: &[u8] = &[
        4, 190, 230, 132, 211, 129, 59, 237, 101, 78, 55, 174, 144, 177, 91, 134, 1, 240, 27, 174,
        81, 139, 8, 22, 32, 241, 228, 103, 189, 43, 44, 102,
    ];
    const TEST3_MRENCLAVE: &[u8] = &[
        4, 190, 230, 132, 211, 129, 59, 237, 101, 78, 55, 174, 144, 177, 91, 134, 1, 240, 27, 174,
        81, 139, 8, 22, 32, 241, 228, 103, 189, 43, 44, 102,
    ];

    // MRSIGNER is 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
    const TEST4_MRENCLAVE: [u8; 32] =
        hex!("7a3454ec8f42e265cb5be7dfd111e1d95ac6076ed82a0948b2e2a45cf17b62a0");
    const TEST5_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    // equal to TEST5!
    const TEST6_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");
    // equal to TEST6!
    const TEST7_MRENCLAVE: [u8; 32] =
        hex!("f4dedfc9e5fcc48443332bc9b23161c34a3c3f5a692eaffdb228db27b704d9d1");

    // unix epoch. must be later than this
    const TEST1_TIMESTAMP: i64 = 1580587262i64;
    const TEST2_TIMESTAMP: i64 = 1581259412i64;
    const TEST3_TIMESTAMP: i64 = 1581259975i64;

    //const CERT: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C914A32A3AE2C4871BFABF22E960C55635869FC66293A3D9B2D58ED96CA620B65D669A444C80291314EF691E896F664317CF80C\",\"isvEnclaveQuoteBody\":\"AgAAAEALAAAIAAcAAAAAAOE6wgoHKsZsnVWSrsWX9kky0kWt9K4xcan0fQ996Ct+CAj//wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFJJYIbPVot9NzRCjW2z9+k+9K8BsHQKzVMEHOR14hNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSVBYWIO9f2OfDtwMd1jofRuPyYiGpL4vUgo/R/1ucl7zyN7gsTIoBsHI7O6mD3IafHSV59DtJ5FnIMCckS1vW\"}|EbPFH/ThUaS/dMZoDKC5EgmdUXUORFtQzF49Umi1P55oeESreJaUvmA0sg/ATSTn5t2e+e6ZoBQIUbLHjcWLMLzK4pJJUeHhok7EfVgoQ378i+eGR9v7ICNDGX7a1rroOe0s1OKxwo/0hid2KWvtAUBvf1BDkqlHy025IOiXWhXFLkb/qQwUZDWzrV4dooMfX5hfqJPi1q9s18SsdLPmhrGBheh9keazeCR9hiLhRO9TbnVgR9zJk43SPXW+pHkbNigW+2STpVAi5ugWaSwBOdK11ZjaEU1paVIpxQnlW1D6dj1Zc3LibMH+ly9ZGrbYtuJks4eRnjPhroPXxlJWpQ==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";
    const CERT_FAKE_QUOTE_STATUS: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"OK\",\"platformInfoBlob\":\"1602006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C914A32A3AE2C4871BFABF22E960C55635869FC66293A3D9B2D58ED96CA620B65D669A444C80291314EF691E896F664317CF80C\",\"isvEnclaveQuoteBody\":\"AgAAAEALAAAIAAcAAAAAAOE6wgoHKsZsnVWSrsWX9kky0kWt9K4xcan0fQ996Ct+CAj//wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFJJYIbPVot9NzRCjW2z9+k+9K8BsHQKzVMEHOR14hNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSVBYWIO9f2OfDtwMd1jofRuPyYiGpL4vUgo/R/1ucl7zyN7gsTIoBsHI7O6mD3IafHSV59DtJ5FnIMCckS1vW\"}|EbPFH/ThUaS/dMZoDKC5EgmdUXUORFtQzF49Umi1P55oeESreJaUvmA0sg/ATSTn5t2e+e6ZoBQIUbLHjcWLMLzK4pJJUeHhok7EfVgoQ378i+eGR9v7ICNDGX7a1rroOe0s1OKxwo/0hid2KWvtAUBvf1BDkqlHy025IOiXWhXFLkb/qQwUZDWzrV4dooMfX5hfqJPi1q9s18SsdLPmhrGBheh9keazeCR9hiLhRO9TbnVgR9zJk43SPXW+pHkbNigW+2STpVAi5ugWaSwBOdK11ZjaEU1paVIpxQnlW1D6dj1Zc3LibMH+ly9ZGrbYtuJks4eRnjPhroPXxlJWpQ==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";
    const CERT_WRONG_PLATFORM_BLOB: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1602006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C914A32A3AE2C4871BFABF22E960C55635869FC66293A3D9B2D58ED96CA620B65D669A444C80291314EF691E896F664317CF80C\",\"isvEnclaveQuoteBody\":\"AgAAAEALAAAIAAcAAAAAAOE6wgoHKsZsnVWSrsWX9kky0kWt9K4xcan0fQ996Ct+CAj//wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFJJYIbPVot9NzRCjW2z9+k+9K8BsHQKzVMEHOR14hNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSVBYWIO9f2OfDtwMd1jofRuPyYiGpL4vUgo/R/1ucl7zyN7gsTIoBsHI7O6mD3IafHSV59DtJ5FnIMCckS1vW\"}|EbPFH/ThUaS/dMZoDKC5EgmdUXUORFtQzF49Umi1P55oeESreJaUvmA0sg/ATSTn5t2e+e6ZoBQIUbLHjcWLMLzK4pJJUeHhok7EfVgoQ378i+eGR9v7ICNDGX7a1rroOe0s1OKxwo/0hid2KWvtAUBvf1BDkqlHy025IOiXWhXFLkb/qQwUZDWzrV4dooMfX5hfqJPi1q9s18SsdLPmhrGBheh9keazeCR9hiLhRO9TbnVgR9zJk43SPXW+pHkbNigW+2STpVAi5ugWaSwBOdK11ZjaEU1paVIpxQnlW1D6dj1Zc3LibMH+ly9ZGrbYtuJks4eRnjPhroPXxlJWpQ==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";
    const CERT_WRONG_SIG: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1602006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C914A32A3AE2C4871BFABF22E960C55635869FC66293A3D9B2D58ED96CA620B65D669A444C80291314EF691E896F664317CF80C\",\"isvEnclaveQuoteBody\":\"AgAAAEALAAAIAAcAAAAAAOE6wgoHKsZsnVWSrsWX9kky0kWt9K4xcan0fQ996Ct+CAj//wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFJJYIbPVot9NzRCjW2z9+k+9K8BsHQKzVMEHOR14hNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSVBYWIO9f2OfDtwMd1jofRuPyYiGpL4vUgo/R/1ucl7zyN7gsTIoBsHI7O6mD3IafHSV59DtJ5FnIMCckS1vW\"}|EbPFH/ThUaS/dMZoDKC5EgmdUXUORFtQzF49Umi1P55oeESreJaUvmA0sg/ATSTn5t2e+e6ZoBQIUbLHjcWLMLzK4pJJUeHhok7EfVgoQ378i+eGR9v7ICNDGX7a1rroOe0s1OKxwo/0hid2KWvtAUBvf1BDkqlHy025IOiXWhXFLkb/qQwUZDWzrV4dooMfX5hfqJPi1q9s18SsdLPmhrGBheh9keazeCR9hiLhRO9TbnVgR9zJk43SPXW+pHkbNigW+2STpVAi5ugWaSwBOdK11ZjaEU1paVIpxQnlW1D6dj1Zc3LibMH+ly9ZGrbYtuJks4eRnjPhroPXxlJWpQ==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEaRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";
    const CERT_TOO_SHORT1: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1602006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C91\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";
    const CERT_TOO_SHORT2: &[u8] = b"0\x82\x0c\x8c0";

    #[test]
    fn verify_ias_report_should_work() {
        let signer_attn: [u32; 16] = Decode::decode(&mut TEST1_SIGNER_ATTN).unwrap();
        let report = verify_ias_report(TEST4_CERT);
        let report = report.unwrap();
        assert_eq!(report.mr_enclave, TEST4_MRENCLAVE);
        assert!(report.timestamp >= TEST1_TIMESTAMP);
        assert_eq!(report.pubkey, TEST4_SIGNER_PUB);
        //assert_eq!(report.status, SgxStatus::GroupOutOfDate);
        assert_eq!(report.status, SgxStatus::ConfigurationNeeded);
    }

    #[test]
    fn verify_zero_length_cert_returns_err() {
        // CERT empty, argument 2 and 3 are wrong too!
        let signer_attn: [u32; 16] = Decode::decode(&mut TEST1_SIGNER_ATTN).unwrap();
        assert!(verify_ias_report(&Vec::new()[..]).is_err())
    }

    #[test]
    fn verify_wrong_cert_is_err() {
        // CERT wrong, argument 2 and 3 are wrong too!
        let signer_attn: [u32; 16] = Decode::decode(&mut TEST1_SIGNER_ATTN).unwrap();
        assert!(verify_ias_report(CERT_WRONG_PLATFORM_BLOB).is_err())
    }

    #[test]
    fn verify_wrong_fake_enclave_quote_is_err() {
        // quote wrong, argument 2 and 3 are wrong too!
        let signer_attn: [u32; 16] = Decode::decode(&mut TEST1_SIGNER_ATTN).unwrap();
        assert!(verify_ias_report(CERT_FAKE_QUOTE_STATUS).is_err())
    }

    #[test]
    fn verify_wrong_sig_is_err() {
        // sig wrong, argument 2 and 3 are wrong too!
        let signer_attn: [u32; 16] = Decode::decode(&mut TEST1_SIGNER_ATTN).unwrap();
        assert!(verify_ias_report(CERT_WRONG_SIG).is_err())
    }

    #[test]
    fn verify_short_cert_is_err() {
        let signer_attn: [u32; 16] = Decode::decode(&mut TEST1_SIGNER_ATTN).unwrap();
        assert!(verify_ias_report(CERT_TOO_SHORT1).is_err());
        assert!(verify_ias_report(CERT_TOO_SHORT2).is_err());
    }

    #[test]
    fn safe_indexing_works() {
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_eq!(safe_indexing(&data, 1, 7), Ok(&data[1..7]));
        assert_eq!(safe_indexing_one(&data, 3), Ok(3));
        assert!(safe_indexing(&data, 1, 8).is_err());
        assert!(safe_indexing(&data, 6, 1).is_err());
        assert!(safe_indexing(&data, 16, 19).is_err());
    }
}
