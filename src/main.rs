mod pass;
mod key_handling;
mod config;

use key_handling::ToPKey;
use key_handling::ToSshAgentPublicKey;

use config::Config;

use std::collections::HashMap;
use std::env::temp_dir;
use std::fs::remove_file;
use std::error;
use std::fmt;

use ssh_agent::agent::Agent;
use ssh_agent::proto::Blob;
use ssh_agent::proto::Identity;
use ssh_agent::proto::Message;
use ssh_agent::proto::PublicKey;
use ssh_agent::proto::SignatureBlob;
use ssh_agent::proto::Signature;

use openssl::sign::Signer;
use openssl::hash::MessageDigest;

#[derive(Debug)]
enum Error {
    ProtoError(ssh_agent::proto::ProtoError),
    PassError(pass::Error),
    KeyError(key_handling::Error),
    OpensslError(openssl::error::ErrorStack),
    MissingPubkeyError,
    UnimplementedError,
}

impl From<ssh_agent::proto::ProtoError> for Error {
    fn from(err: ssh_agent::proto::ProtoError) -> Self {
        Error::ProtoError(err)
    }
}

impl From<pass::Error> for Error {
    fn from(err: pass::Error) -> Self {
        Error::PassError(err)
    }
}

impl From<key_handling::Error> for Error {
    fn from(err: key_handling::Error) -> Self {
        Error::KeyError(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Error::OpensslError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ProtoError(_) =>
                write!(f, "Failed to read public SSH key format."),
            Self::PassError(_) =>
                write!(f, "The pass binary failed."),
            Self::KeyError(_) =>
                write!(f, "Something went wrong parsing or using the keys."),
            Self::OpensslError(_) =>
                write!(f, "OpenSsl failed to sign the payload."),
            Self::MissingPubkeyError =>
                write!(f, "Public key is not in cache."),
            Self::UnimplementedError =>
                write!(f, "The SSH-Agent protocol is not fully implemented.")
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::ProtoError(err) => Some(err),
            Self::PassError(err) => Some(err),
            Self::KeyError(err) => Some(err),
            Self::OpensslError(err) => Some(err),
            Self::MissingPubkeyError => None,
            Self::UnimplementedError => None,
        }
    }
}

struct PassSshAgent {
    /// The query string passed to `pass show'.
    config: Config,
    key_map: HashMap<PublicKey, String>,
}

impl PassSshAgent {
    fn new() -> Self {
        let config = Config::new("../tests/config.toml").unwrap();
        let key_map = HashMap::new();

        let mut agent = Self {
            config,
            key_map,
        };

        agent.build_cache();
        agent
    }

    /// Go through all the public keys in the pass database and
    /// map them to their corresponding locations in pass
    fn build_cache(&mut self) {
        for (privkey_query, pubkey_query) in self.config.keypairs.iter() {
            let pubkey = pass::query(pubkey_query.to_owned()).unwrap();

            self.key_map.insert(
                pubkey.to_ssh_agent_key().unwrap(),
                String::from(privkey_query),
            );
        }
    }

    /// Return a list of identity objects representing every managed pubkey
    fn get_identities(&self) -> Vec<Identity> {
        // The public keys are cached as the keys of the key map
        self.key_map.keys().map(|pubkey|
            Identity {
                pubkey_blob: pubkey.to_blob().unwrap(),
                comment: String::new(),
            }
        )
        .collect()
    }

    /// Sign the given data using the private key corresponding to the given
    /// pubkey blob
    fn sign(&self, pubkey_blob: &Vec<u8>, data: &Vec<u8>) -> Result<SignatureBlob, Error> {
        // Check if the given public key is in the cache
        let pubkey = &PublicKey::from_blob(pubkey_blob)?;

        if !self.key_map.contains_key(pubkey) {
            return Err(Error::MissingPubkeyError);
        }

        // Get the privkey from pass using the cached query
        let privkey_query = &self.key_map[pubkey];
        let privkey_raw = pass::query(privkey_query.to_owned())?;
        let privkey = privkey_raw.to_private_key()?;

        // Sign the message using sha-512 (supported by default on newer openssh instances)
        let mut signer = Signer::new(MessageDigest::sha512(), &privkey)?;
        signer.update(data)?;
        let signature = Signature {
            algorithm: String::from("rsa-sha2-512"),
            blob: signer.sign_to_vec()?,
        };

        Ok(signature.to_blob()?)
    }

    /// Generate a response to a message from a client.
    fn handle(&self, message: Message) -> Result<Message, Error> {
        match message {
            Message::RequestIdentities =>
                Ok(Message::IdentitiesAnswer(self.get_identities())),
            Message::SignRequest( ssh_agent::proto::SignRequest {
                pubkey_blob,
                data,
                ..
            }) =>
                Ok(Message::SignResponse(self.sign(&pubkey_blob, &data)?)),
            _ => Err(Error::UnimplementedError),
        }
    }
}

impl Agent for PassSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
        self.handle(message).or(Ok(Message::Failure))
    }
}

fn main() {
    let agent = PassSshAgent::new();

    let sockfile = temp_dir().join("passh-agent.sock");
    remove_file(&sockfile).ok();

    agent.run_unix(sockfile).unwrap();
}
