# passh-agent
An ssh-agent that fetches SSH keys from the Pass password manager.

## Implementation
Passh-agent does not cache any private keys - it makes calls to pass anytime
private keys are needed, so they are decrypted on-demand.
This allows integration the of agent with the GPG password caching you would
generally expect a pass user to have setup.
It *does* cache public keys, for easy lookup of private keys.

Passh-agent implements just the necessary parts of the ssh-agent protocol to
allow for signing and verifying messages.
Specifically, it does not implement adding keypairs using ssh-add,
as keys are added to the agent through a minimal configuration file.

## Limitations
For now, the agent only works with PEM-formatted RSA private keys and
openssh-formatted RSA public keys.
This setup will be the default if you generated your keys some time
ago, but more recently generated keys by default use a proprietary private
key format. You'll have to convert the private key to PEM RSA.

## Configuration
The configuration file is located at `$XDG_CONFIG_HOME/passh-agent/keys.toml` if
`$XDG_CONFIG_HOME` is set, otherwise it is at `$HOME/.config/passh-agent/keys.toml`.

To add a keypair to the agent, create a new section in the configuration file,
specifying the locations of your public- and private keys in pass:

```
[Work]
privkey = "ssh/work/id_rsa"
pubkey = "ssh/work/id_rsa.pub"

[Home]
privkey = "ssh/id_rsa"
pubkey = "ssh/id_rsa.pub"
```

The agent caches the public keys for faster lookup, so if a keypair is added at
runtime, the agent must be restarted.

The agent has no default configuration.

## Roadmap
Passh-agent is now barely functional, but many features have yet to be added.
Planned/implemented features:
 - [x] Openssh public key support (RSA)
 - [ ] Openssh public key support (other key types)
 - [ ] Openssh private key support
 - [x] PEM private key support (RSA)
 - [ ] PEM private key support (other key types)
 - [ ] PEM public key support
 - [ ] Optional filesystem storage for public keys
 - [ ] Regular expressions to configure keypairs
