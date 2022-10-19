use std::error;
use std::fmt;

use ssh_agent_lib::proto::public_key as agent_public_key;
use ssh_agent_lib::proto::PublicKey;

use openssl::bn::BigNum;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

use base64;
use byteorder::BigEndian;
use byteorder::ByteOrder;

#[derive(Debug)]
pub enum Error {
    ParseError(openssl::error::ErrorStack),
    DecodeError(base64::DecodeError),
    MultiKeyError,
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Error::ParseError(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::DecodeError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ParseError(_) | Self::DecodeError(_) =>
                write!(f, "Something went wrong trying to parse the given key."),
            Self::MultiKeyError =>
                write!(f, "Private key contained multiple keys for single identity."),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ParseError(err) => Some(err),
            Self::DecodeError(err) => Some(err),
            Self::MultiKeyError => None,
        }
    }
}

pub trait ToPKey {
    fn to_private_key(&self) -> Result<PKey<Private>, Error>;
    fn to_public_key(&self) -> Result<PKey<Public>, Error>;
}

impl ToPKey for String {
    fn to_private_key(&self) -> Result<PKey<Private>, Error>  {
        let key = PKey::private_key_from_pem(self.as_bytes())?;
        key.rsa()?;
        Ok(key)
    }

    fn to_public_key(&self) -> Result<PKey<Public>, Error> {
        // TODO: Deal with PEM public keys, also
        // Split the openssh key into the type and data
        let line: String = self.lines().map(|ln| ln.trim()).collect();
        let words: Vec<_> = line.split_whitespace().collect();
        let (key_type, raw) = match words.as_slice() {
            [key_type, raw, ..] => (*key_type, *raw),
            _ => todo!(),
        };
        
        // Decode the key
        let raw = base64::decode(raw)?;

        let key = match key_type {
            "ssh-rsa" => {
                // Extract the different components from the raw bytes in an
                // openssh-formatted public key
                let end_k = BigEndian::read_u32(&raw[..4]) as usize + 4;
                let end_e = BigEndian::read_u32(&raw[end_k..end_k+4]) as usize + end_k + 4;
                let end_n = BigEndian::read_u32(&raw[end_e..end_e+4]) as usize + end_e + 4;

                let e = BigNum::from_slice(&raw[end_k+4..end_e])?;
                let n = BigNum::from_slice(&raw[end_e+4..end_n])?;

                PKey::from_rsa(
                    Rsa::from_public_components(n, e)?
                )?
            },
            _ => todo!(),
        };

        Ok(key)
    }
}

pub trait ToSshAgentPublicKey {
    fn to_ssh_agent_key(&self) -> Result<PublicKey, Error>;
}

impl ToSshAgentPublicKey for String {
    fn to_ssh_agent_key(&self) -> Result<PublicKey, Error> {
        let pkey = self.to_public_key()?;
        let agent_key = pkey.to_ssh_agent_key()?;

        Ok(agent_key)
    }
}

impl ToSshAgentPublicKey for PKey<Public> {
    fn to_ssh_agent_key(&self) -> Result<PublicKey, Error> {
        let mut n = self.rsa()?.n().to_vec();
        let e = self.rsa()?.e().to_vec();

        n.insert(0, 0);

        Ok(PublicKey::Rsa(agent_public_key::RsaPublicKey {
            n,
            e,
        }))
    }
}
