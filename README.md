# RFC 2069 Digest Access Authentication Crack

Legacy digest authentication password bruteforce. Requires an intercepted authentication packet.

# Compilation

```gcc main.c -lcrypto```

Depends on OpenSSL/evp.h for md5 hashing.

# Usage

```
./program details.txt passwords.txt [-vq]
-v prints every attempt, -q hides progress messages
detail file contents:
user=%s\n
realm=%s\n
method=%s\n
uri=%s\n
nonce=%s\n
response=%s\n
```


Check the goat_details.txt for an example. The password should be in most wordlists.
passwords.txt should have one plaintext password per line.

Example TCP packet going from a PC to an IP Camera, captured with Wireshark:

```
DESCRIBE rtsp://192.168.1.205:554/live1.sdp RTSP/1.0
Accept: application/sdp
CSeq: 3
User-Agent: libmpv
Authorization: Digest username="admin", realm="DCS-2132LB1", nonce="0fba0c387cfc24262e910944d035eaaf", uri="rtsp://192.168.1.205:554/live1.sdp", response="096a5a7f66e0f96984d3a5beb317ed28"
```

# License

GPL 3

# Disclaimer

crime bad

thus dont
