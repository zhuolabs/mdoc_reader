use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use mdoc_core::{CoseKeyPrivate, CoseKeyPublic, SessionTranscript, TaggedCborBytes};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdocRole {
    Reader,
    Device,
}

pub struct SessionEncryption {
    role: MdocRole,
    sk_self: [u8; 32],
    sk_remote: [u8; 32],
}

impl SessionEncryption {
    pub fn new(
        role: MdocRole,
        e_self_private_key: &CoseKeyPrivate,
        remote_public_key: &CoseKeyPublic,
        session_transcript: &TaggedCborBytes<SessionTranscript>,
    ) -> Result<Self> {
        let shared_secret = derive_shared_secret(e_self_private_key, remote_public_key)?;
        let (sk_device, sk_reader) = derive_session_keys(&shared_secret, session_transcript)?;
        let (sk_self, sk_remote) = match role {
            MdocRole::Device => (sk_device, sk_reader),
            MdocRole::Reader => (sk_reader, sk_device),
        };

        Ok(Self {
            role,
            sk_self,
            sk_remote,
        })
    }

    pub fn encrypt_data(&self, plaintext: &[u8], counter: u32) -> Result<Vec<u8>> {
        let iv_identifier = match self.role {
            MdocRole::Device => 1,
            MdocRole::Reader => 0,
        };
        let iv = build_iv(iv_identifier, counter);
        let cipher = Aes256Gcm::new_from_slice(&self.sk_self)
            .map_err(|e| anyhow::anyhow!("failed to initialize cipher: {}", e))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&iv), plaintext)
            .map_err(|e| anyhow::anyhow!("failed to encrypt data: {}", e))?;
        Ok(ciphertext)
    }

    pub fn decrypt_data(&self, ciphertext: &[u8], counter: u32) -> Result<Vec<u8>> {
        let iv_identifier = match self.role {
            MdocRole::Device => 0,
            MdocRole::Reader => 1,
        };
        let iv = build_iv(iv_identifier, counter);
        let cipher = Aes256Gcm::new_from_slice(&self.sk_remote)
            .map_err(|e| anyhow::anyhow!("failed to initialize cipher: {}", e))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&iv), ciphertext)
            .map_err(|e| anyhow::anyhow!("failed to decrypt data: {}", e))?;
        Ok(plaintext)
    }
}

pub fn derive_shared_key(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| anyhow::anyhow!("HKDF key derivation failed"))?;
    Ok(output)
}

pub fn derive_shared_secret(
    e_self_private_key: &CoseKeyPrivate,
    remote_public_key: &CoseKeyPublic,
) -> Result<[u8; 32]> {
    let secret_key = SecretKey::try_from(e_self_private_key)?;
    let remote_public_key = PublicKey::try_from(remote_public_key)?;
    let shared_secret = diffie_hellman(
        secret_key.to_nonzero_scalar(),
        remote_public_key.as_affine(),
    );
    Ok((*shared_secret.raw_secret_bytes()).into())
}

fn derive_session_keys(
    shared_secret: &[u8; 32],
    session_transcript: &TaggedCborBytes<SessionTranscript>,
) -> Result<([u8; 32], [u8; 32])> {
    let salt = Sha256::digest(minicbor::to_vec(session_transcript)?);
    let sk_device = derive_shared_key(shared_secret, &salt, b"SKDevice")?;
    let sk_reader = derive_shared_key(shared_secret, &salt, b"SKReader")?;
    Ok((sk_device, sk_reader))
}

fn build_iv(iv_identifier: u32, counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[4..8].copy_from_slice(&iv_identifier.to_be_bytes());
    iv[8..12].copy_from_slice(&counter.to_be_bytes());
    iv
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;
    use mdoc_core::SessionEstablishment;
    use minicbor::bytes::ByteVec;
    use minicbor::Encoder;

    const SESSION_TRANSCRIPT_BYTES: &str = "d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414";
    const DEVICE_REQUEST: &str = "a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d8185893a267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a1716f72672e69736f2e31383031332e352e31a66b66616d696c795f6e616d65f56f646f63756d656e745f6e756d626572f57264726976696e675f70726976696c65676573f56a69737375655f64617465f56b6578706972795f64617465f568706f727472616974f46a726561646572417574688443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba175dc945755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f74301e170d3230313030313030303030305a170d3233313233313030303030305a3011310f300d06035504030c067265616465723059301306072a8648ce3d020106082a8648ce3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628dff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f30b464fada20bfcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d0403020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d739dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f631427c589424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf";
    const EPHEMERAL_READER_KEY_D: &str =
        "de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c";
    const EPHEMERAL_READER_KEY_X: &str =
        "60e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e";
    const EPHEMERAL_READER_KEY_Y: &str =
        "e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa";
    const EPHEMERAL_DEVICE_KEY_X: &str =
        "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe";
    const EPHEMERAL_DEVICE_KEY_Y: &str =
        "b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67";
    const SESSION_ESTABLISHMENT: &str = "a26a655265616465724b6579d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa64646174615902df52ada2acbeb6c390f2ca0bc659b484678eb94dd45074386aadece23777b44606e42e2846bc2e2ee3c1e867b1d1685e41354a021abb0fda36f09cf5d5c51b561d3be41c9347ae71cf2b49de9dec7b44046ab02247931b210c9157840c1514a6027b08810716adf61966344979314ac3ae9f40e66e015c1254a684108bd093e8772ec333fb663fd6803af02ea10bdbe83a999f75b55a180f872139fb57ac04acd58ca15eca150cde1c3b849401188b7a30ce887dd7b71b12eda2fc6ec6e5235a6c9498351fcd301f2292a4ebba7555285cee84ead96ef1677b0af8239f6a7a52af4b8809b1d52ab21a162ca31ade21c57bd1d9970a2832aac41c7d52d1c4fee4ee64030a218df51363be701792fa6c515c489bd39dcad6fba48f1d6eb19e9c769531a3bf9998a32c01841305f23844ca3db6a1ff0d0d917343d62fc72ad58eab01a3198116f19606609f94e35eacb78d23c59c67852a361915fe87848cdba5630c99fab71aeff72d131cf442654f7708ec48216416f2d996cf6cf91012b771b88907b1d1629dfa794343e653c31207482e2f6621cd4b5dcf3b3c328625c33fe98be99c5f264a264315be41bafdc726f8bcde5920de0a71884d860af44c1ff1b3d78b2e8d720d85dae53fea2b3fa1806162a4be02d039567c5eb2419c2ad879af48fcb7df55ca94f1b00f62187fa2329c8227aae0130ec052ca3e2102e57e72911b328cfdcfbaaf6b9364660f613415382644c30c0bd4e222c5cf94ba5a73679c53d5ced95ca50787c2289a0c17358393c1e0f2272361002fb9b160606888a59ef7a2c389f68b7cb424572db026b17cf2bdcafcb67c8292d92b50050356900a62a82b16f854759052b00f0f4673a46229f43257e8e8325401b3fecc8c6d2258baf7f7c2fbbafab3a1b6aded4eceac1eafd5b61118df93bc0a622b03504fde47cebb224e983db12677e316c22aae042d6ce4adae0d8b0f40437b8e1afa0859c9501beb63974496859a60f11069b1965b4ffac5779a96191f89eac7caa688b9e67c";

    #[tokio::test]
    async fn reader_session_encryption_matches_annex_d_vectors() {
        let encoded_session_transcript = tagged_cbor_to_inner(SESSION_TRANSCRIPT_BYTES);
        let e_device_key = encode_ec2_public_key(EPHEMERAL_DEVICE_KEY_X, EPHEMERAL_DEVICE_KEY_Y);
        let e_reader_key = encode_ec2_private_key(
            EPHEMERAL_READER_KEY_X,
            EPHEMERAL_READER_KEY_Y,
            EPHEMERAL_READER_KEY_D,
        );
        let e_reader_public = encode_ec2_public_key(EPHEMERAL_READER_KEY_X, EPHEMERAL_READER_KEY_Y);
        let session_transcript: SessionTranscript =
            minicbor::decode(&encoded_session_transcript).unwrap();
        let e_device_key: CoseKeyPublic = minicbor::decode(&e_device_key).unwrap();
        let e_reader_public: CoseKeyPublic = minicbor::decode(&e_reader_public).unwrap();
        let e_reader_key: CoseKeyPrivate = minicbor::decode(&e_reader_key).unwrap();

        let session = SessionEncryption::new(
            MdocRole::Reader,
            &e_reader_key,
            &e_device_key,
            &TaggedCborBytes::from(&session_transcript),
        )
        .unwrap();

        let session_establishment = SessionEstablishment {
            e_reader_key: TaggedCborBytes::from(&e_reader_public),
            data: ByteVec::from(
                session
                    .encrypt_data(&decode(DEVICE_REQUEST).unwrap(), 1)
                    .unwrap(),
            ),
        };

        assert_eq!(
            minicbor::to_vec(session_establishment).unwrap(),
            decode(SESSION_ESTABLISHMENT).unwrap()
        );
    }

    fn tagged_cbor_to_inner(hex_value: &str) -> Vec<u8> {
        let bytes = decode(hex_value).unwrap();
        let tagged: minicbor::data::Tagged<24, minicbor::bytes::ByteVec> =
            minicbor::decode(&bytes).unwrap();
        (*tagged).to_vec()
    }

    fn encode_ec2_public_key(x: &str, y: &str) -> Vec<u8> {
        let x = decode(x).unwrap();
        let y = decode(y).unwrap();
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(4).unwrap();
        encoder.i8(1).unwrap();
        encoder.i8(2).unwrap();
        encoder.i8(-1).unwrap();
        encoder.i8(1).unwrap();
        encoder.i8(-2).unwrap();
        encoder.bytes(&x).unwrap();
        encoder.i8(-3).unwrap();
        encoder.bytes(&y).unwrap();
        encoder.into_writer()
    }

    fn encode_ec2_private_key(x: &str, y: &str, d: &str) -> Vec<u8> {
        let x = decode(x).unwrap();
        let y = decode(y).unwrap();
        let d = decode(d).unwrap();
        let mut encoder = Encoder::new(Vec::new());
        encoder.map(5).unwrap();
        encoder.i8(1).unwrap();
        encoder.i8(2).unwrap();
        encoder.i8(-1).unwrap();
        encoder.i8(1).unwrap();
        encoder.i8(-2).unwrap();
        encoder.bytes(&x).unwrap();
        encoder.i8(-3).unwrap();
        encoder.bytes(&y).unwrap();
        encoder.i8(-4).unwrap();
        encoder.bytes(&d).unwrap();
        encoder.into_writer()
    }
}
