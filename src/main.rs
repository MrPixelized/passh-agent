mod pass;
mod key_handling;
mod config;

use key_handling::ToSshAgentKey;
use config::Config;

use std::collections::HashMap;

use ssh_agent::agent::Agent;
use ssh_agent::proto::Blob;
use ssh_agent::proto::Message;
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::Identity;

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
                pubkey.to_public_key().unwrap(),
                String::from(privkey_query),
            );
        }
    }

    /// Return a list of identity objects representing every managed pubkey
    fn get_identities(&self) -> Vec<Identity> {
        self.key_map.keys().map(|pubkey| 
            Identity {
                pubkey_blob: pubkey.to_blob().unwrap(),
                comment: String::new(),
            }
        )
        .collect()
    }

    /// Generate a response to a message from a client.
    fn handle(&self, message: Message) -> Result<Message, ()> {
        match message {
            Message::RequestIdentities => Ok(Message::IdentitiesAnswer(self.get_identities())),
            _ => Err(()),
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

    println!("{:?}", agent.get_identities());
}
