use std::error;
use std::fmt;

use ssh_agent::proto::private_key as agent_private_key;
use ssh_agent::proto::public_key as agent_public_key;
use ssh_keys::PrivateKey;
use ssh_keys::PublicKey;
use ssh_keys::openssh::parse_private_key;
use ssh_keys::openssh::parse_public_key;

#[derive(Debug)]
pub enum Error {
    ParseError(ssh_keys::Error)
}

impl From<ssh_keys::Error> for Error {
    fn from(err: ssh_keys::Error) -> Self {
        Error::ParseError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ParseError(_) =>
                write!(f, "Something went wrong trying to parse the given key."),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ParseError(err) => Some(err),
        }
    }
}

pub trait ToSshAgentKey {
    fn to_private_key(&self) -> Result<Vec<agent_private_key::PrivateKey>, Error>;
    fn to_public_key(&self) -> Result<agent_public_key::PublicKey, Error>;
}

impl ToSshAgentKey for String {
    fn to_private_key(&self) -> Result<Vec<agent_private_key::PrivateKey>, Error>  {
        let keys = parse_private_key(self)?;

        let agent_keys = keys.into_iter().map(|key| match key {
            PrivateKey::Rsa {
                n, e, d, iqmp, p, q
            } => agent_private_key::PrivateKey::Rsa (
                agent_private_key::RsaPrivateKey {
                    n: n.to_owned(),
                    e: e.to_owned(),
                    d: d.to_owned(),
                    iqmp: iqmp.to_owned(),
                    p: p.to_owned(),
                    q: q.to_owned(),
                }
            ),
            _ => todo!(),
        })
        .collect();

        Ok(agent_keys)
    }

    fn to_public_key(&self) -> Result<agent_public_key::PublicKey, Error> {
        let key = parse_public_key(self)?;

        let agent_keys = match key {
            PublicKey::Rsa {
                exponent, modulus
            } => agent_public_key::PublicKey::Rsa (
                agent_public_key::RsaPublicKey {
                e: exponent,
                n: modulus,
                }
            ),
            _ => todo!(),
        };

        Ok(agent_keys)
    }
}