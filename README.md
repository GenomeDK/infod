# infod

You have a lot of servers. You also have a lot of users. Life's too short for using LDAP.

`infod` is a *very simple* service that can replace YP/NIS in most setups. The server reads a passwd, group, shadow, and a mounts file from disk at serves these to a client.

* It's safer than YP/NIS, because all communication between the client and server is encrypted and authenticated through a shared secret.
* It's more resilient than YP/NIS, because the client stores a copy of the user database on local disk. So even if the server is down, users will be able to log in.
* It's super flexible. You just generate the files any way you want and restart the service. In a matter of seconds, the changes will have been distributed to the clients.
