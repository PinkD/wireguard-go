# wg-corplink

魔改版 [wg-go](https://github.com/WireGuard/wireguard-go) ，仅供 [corplink-rs](https://github.com/PinkD/corplink-rs) 使用

该分枝为静态链接库版本，如需独立二进制版本，请使用 [master](https://github.com/PinkD/wireguard-go/tree/master) 分枝

## Embedded client transport security

The `libwg` TCP client uses an outbound connection to each configured gateway;
responses continue to travel over that full-duplex connection. It does not open
an inbound TCP listener. `conn.NewTCPBind` remains available for server callers.
TCP frames must contain 1–65535 bytes. Connections have bounded dial/write and
partial-frame deadlines, a two-minute idle read deadline, and a limit of 128
simultaneous peers; an idle or failed connection is redialed on subsequent send.

The SOCKS proxy requires both a username and password for a non-loopback
listener. Supplying only one credential is rejected. With credentials configured,
clients must authenticate; the no-auth method is not accepted. The listener and
its active sessions close when the embedded device stops. SOCKS handshakes have
a ten-second deadline and at most 128 simultaneous sessions are accepted. TCP
and UDP forwarding share a limit of 128 established target connections; new
destinations are refused while the limit is reached. Closing a session releases
its targets, and closing the service releases all targets.

SOCKS UDP ASSOCIATE clients must bind their UDP socket **before** sending the
TCP request and include that socket's nonzero source port. An unspecified source
IP is replaced with the authenticated TCP peer's IP; a different IP or source
port is rejected. Requests using source port `0` receive SOCKS "connection not
allowed by ruleset". Such clients can still use SOCKS TCP CONNECT, or must be
configured/updated to announce their bound UDP port. Learning a port from the
first UDP packet is deliberately unsupported because another local user can
win that race, including on loopback. NAT must preserve the announced source
port. The local UDP handler enforces this source check, closes its listener even
if the initial reply fails, and rejects unsupported fragmented datagrams. The
pinned `go-socks5` v0.1.4 supplies authentication and packet parsing; its default
UDP handler is bypassed. These checks are not a complete dependency audit.
