# infod

You have a lot of servers. You also have a lot of users. Life's too short for using LDAP.

`infod` is a *very simple* service that can replace YP/NIS in most setups. The server reads arbitrary files from disk and serves these to a its clients.

* It's safer than YP/NIS, because all communication between the client and server is encrypted and authenticated through a shared secret.
* It's more resilient than YP/NIS, because the client stores a copy of the user database on local disk. So even if the server is down, users will be able to log in.
* It's super flexible. You just generate the files any way you want and restart the service. In a matter of seconds, the changes will have been distributed to the clients.

This repository contains a server that can serve files to the clients. The clients writes the files (atomically) with the specified mode. We also provide an NSS module that reads specific files (passwd, group, shadow) and provides these to the system.

## Configuration



```toml
secret_key = "hejmeddigjeghedderkaj"

[server]
listen_on = "0.0.0.0:9797"
files = [
    { src = "/var/spool/infod_server/passwd", dest = "/var/spool/infod/passwd", mode = 0o644 },
    { src = "/var/spool/infod_server/group", dest = "/var/spool/infod/group", mode = 0o644 },
    { src = "/var/spool/infod_server/shadow", dest = "/var/spool/infod/shadow", mode = 0o000 },
    { src = "/var/spool/infod_server/auto.home", dest = "/var/spool/infod/auto.home", mode = 0o600 },
]

[client]
server = "localhost:9797"
update_interval = 1.0
``````
