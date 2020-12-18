use std::error;
use std::fmt;

use ssh_agent::proto::private_key::PrivateKey as SshAgentPrivateKey;
use ssh_agent::proto::private_key::RsaPrivateKey as SshAgentRsaPrivateKey;
use ssh_keys::PrivateKey;
use ssh_keys::openssh::parse_private_key;

#[derive(Debug)]
pub enum Error {
    ParseError(ssh_keys::Error)
}

impl From<ssh_keys::Error> for Error {
    fn from(err: ssh_keys::Error) -> Error {
        Error::ParseError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ParseError(..) =>
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

pub trait ToSshAgentPrivateKey {
    fn to_private_key(&self) -> Result<Vec<SshAgentPrivateKey>, Error>;
}

impl ToSshAgentPrivateKey for String {
    fn to_private_key(&self) -> Result<Vec<SshAgentPrivateKey>, Error>  {
        let keys = parse_private_key(self)?;

        let agent_keys = keys.into_iter().map(|key| match key {
            PrivateKey::Rsa {
                n, e, d, iqmp, p, q
            } => SshAgentPrivateKey::Rsa (
                SshAgentRsaPrivateKey {
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
        .collect::<Vec<SshAgentPrivateKey>>();

        Ok(agent_keys)
    }
}

