# passh-agent
An ssh-agent that fetches SSH keys from the Pass password manager,
written in Rust.

## Installation
Passh-agent is available as a package on the AUR: `passh-agent-bin`.

The agent's socket is located at `$XDG_RUNTIME_DIR/passh-agent.sock`,
which will typically be `/run/user/[your UID]/passh-agent.sock`. In order for
SSH to interface with the agent, the `SSH_AUTH_SOCK` environment can be
set to this path.

Alternatively, you can put the following line at the top of `~/.ssh/config`:

```
IdentityAgent "/var/run/user/[your UID]/passh-agent.sock"
```

To make sure the ssh command looks to passh-agent for key-related business.
The `id` command will tell you your UID on Linux.

To use the agent throughout an entire user session it will need to be started
at login through, for example, a systemd user service or by putting it in
X11's init scripts. The AUR package also comes with a systemd user service.
If you wish to make use of it, run

```
systemctl --user enable passh-agent.service
systemctl --user start passh-agent.service
```

after installing the package.

Be sure to read through **limitations** if you are not sure of what kind of private
key you have.

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

## Limitations
 - For now, the agent only works with PEM-formatted RSA private keys and
openssh-formatted RSA public keys.
This setup will be the default if you generated your keys some time
ago, but more recently generated keys by default use a proprietary private
key format. You'll have to convert the private key to PEM RSA.
To convert the new openssh format private key to PEM,
you can use the command ``` ssh-keygen -f [path to your key] -m pem -p ```.
Make sure to set an empty password for the key.
The conversion will be done in-place.

 - To add a new key to the agent, it needs to be restarted.

## Implementation
Passh-agent does not cache any private keys - it makes calls to pass anytime
private keys are needed, so they are decrypted on-demand.
This allows for integration of the agent with the GPG password caching you
would generally expect a pass user to have setup.
It *does* cache public keys, for easy lookup of private keys.

Passh-agent implements just the necessary parts of the ssh-agent protocol to
allow for signing and verifying messages.
Specifically, it does not implement adding keypairs using ssh-add,
as keys are added to the agent through a minimal configuration file.

## Testing
Running the unit tests written for this program requires that you have
a valid private key at `ssh/id_rsa` and a valid public key at `ssh/id_rsa.pub`
in your pass password store.

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
 - [ ] On-demand loading of public keys (possibly?)
 - [x] Systemd user service provided with the AUR package
