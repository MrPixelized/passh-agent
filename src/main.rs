mod pass;

use std::env::args_os;

use ssh_agent::agent::Agent;
use ssh_agent::proto::Message;

struct PassSshAgent {
    /// The query string passed to `pass show'.
    // TODO: Query string is to support templating, e.g. `{connection-host}/id_rsa'
    query: String,
}

impl PassSshAgent {
    fn new(query: String) -> Self {
        Self { query }
    }

    /// Generate a response to a message from a client.
    fn handle(&self, message: Message) -> Result<Message, ()> {
    }
}

impl Agent for PassSshAgent {
    type Error = ();

    fn handle(&self, message: Message) -> Result<Message, ()> {
    }
}

fn main() {
    let query = match args_os().nth(1) {
        Some(query) => query.into_string().unwrap(),
        None => String::from("ssh/id_rsa"),
    };

    let agent = PassSshAgent::new(query);
}
