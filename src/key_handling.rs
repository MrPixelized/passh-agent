use std::error;
use std::fmt;

use ssh_agent::proto::public_key as agent_public_key;
use ssh_agent::proto::PublicKey;

use openssl::rsa::Rsa;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::pkey::PKey;
use openssl::bn::BigNum;

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
        let words: Vec<_> = self.split_whitespace().collect();

        let (key_type, raw) = match words.as_slice() {
            [key_type, raw, ..] => (*key_type, *raw),
            _ => todo!(),
        };

        let raw = base64::decode(raw)?;

        let key = match key_type {
            "ssh-rsa" => {
                let size_e = BigEndian::read_u32(&raw[..4]) as usize;
                let e = &raw[4..size_e+4];

                let size_n = BigEndian::read_u32(&raw[size_e+4..size_e+8]) as usize;
                let n = &raw[size_e+4..size_e+8+size_n];

                PKey::from_rsa(
                    Rsa::from_public_components(BigNum::from_slice(n)?, BigNum::from_slice(e)?)?
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

impl ToSshAgentPublicKey for PKey<Public> {
    fn to_ssh_agent_key(&self) -> Result<PublicKey, Error> {
        let n = self.rsa()?.n().to_vec();
        let e = self.rsa()?.e().to_vec();

        Ok(PublicKey::Rsa(agent_public_key::RsaPublicKey {
            n,
            e,
        }))
    }
}
