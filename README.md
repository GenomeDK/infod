# infod

You have a lot of servers. You also have a lot of users. Life's too short for
using LDAP.

`infod` is a *very simple* service that can replace YP/NIS in most setups. The
server reads arbitrary files from disk and serves these to a its clients.

* It's safer than YP/NIS, because all communication between the client and
  server is encrypted and authenticated through a shared secret.
* It's more resilient than YP/NIS, because the client stores a copy of the user
  database on local disk. So even if the server is down, users will be able to
  log in.
* It's super flexible. You just generate the files any way you want and restart
  the service. In a matter of seconds, the changes will have been distributed to
  the clients.

This repository contains a server that can serve files to the clients. The
clients writes the files (atomically) with the specified mode. We also provide
an NSS module that reads specific files (passwd, group, shadow) and provides
these to the system.

`infod` is released under the MIT license.

## Installation

To build and install `infod` you'll need Rust installed on your system. Then run:

```bash
$ git clone git@github.com:GenomeDK/infod.git
$ cd infod/
$ cargo build --workspace --release
```

The binary assets will be located in `target/release/{infod_server,infod_client,libnss_infod.o}`.

You can install `infod` manually:

```bash
$ install -m 555 target/release/{infod_server,infod_client,infoctl} /usr/bin/
$ install -m 555 target/release/libnss_infod.o.2 /usr/lib/libnss_infod.so.2
$ install -m 600 -d config.example.toml /etc/infod/config.toml
$ install -m 600 -d infod-server.example.service /etc/systemd/system/infod-server.service
$ install -m 600 -d infod-client.example.service /etc/systemd/system/infod-client.service
```

Or build RPMs:

```bash
$ cargo generate-rpm -p infod_server
$ cargo generate-rpm -p infod_client
$ cargo generate-rpm -p infod_nss
$ cargo generate-rpm -p infoctl
```

The RPMs will be available in `target/generate-rpm/` and are compatible with
RedHat-derivatives version 8 or newer. If you need packages compatible with e.g.
CentOS 7, use the `--payload-compress none` option when generating the RPMs.

## Configuration

The configuration looks like this:

```toml
secret_key = "hejmeddigjeghedderkaj"

[server]
listen_on = "0.0.0.0:9797"
files = [
    { src = "/var/spool/infod_server/passwd", dest = "/var/spool/infod/passwd", mode = 0o444 },
    { src = "/var/spool/infod_server/group", dest = "/var/spool/infod/group", mode = 0o444 },
    { src = "/var/spool/infod_server/shadow", dest = "/var/spool/infod/shadow", mode = 0o000 },
    { src = "/var/spool/infod_server/auto.home", dest = "/var/spool/infod/auto.home", mode = 0o400 },
]

[client]
server = "localhost:9797"
update_interval = 1.0
```

The configuration should be modified to suit your needs. Remember to set
`secret_key` to something long and secret.

You can then tell NSS to use `infod` by modifying `/etc/nsswitch.conf`:

```bash
passwd:     files infod
shadow:     files infod
group:      files infod
...
```

The infod NSS module expects the passwd, group, and shadow files to be written
to `/var/spool/infod/` directory, as shown in the example config above.

For `autofs` mounts, you can tell it to use the local maps with in
`/etc/auto.master`:

```bash
/home       file:/var/spool/infod/auto.home        --timeout=60
...
```
