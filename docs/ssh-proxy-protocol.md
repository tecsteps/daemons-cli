# SSH proxy control protocol

`daemons ssh-proxy` connects to the gateway `/ssh` endpoint using exactly one
WebSocket subprotocol: `dr.<one-use-ticket>`. WebSocket compression is off.

Before the gateway emits any binary SSH payload it sends one text frame exactly
`{"type":"ready"}`. The helper must consume it before reading or writing SSH
payload. Admission refusal is a text frame `{"type":"error","code":"…","message":"…"}`;
the helper writes its diagnostic only to stderr and exits non-zero.

After ready, every SSH byte is carried in binary frames without encoding or
inspection. On local stdin EOF the helper sends the one text control frame
`{"type":"eof"}`. The gateway closes only its relay stdin leg, continues
draining relay stdout as binary frames, then closes the WebSocket. No other
text frames are valid. A binary frame may be at most 1 MiB; the helper accepts
that full bound so normal 64 KiB relay chunks are not mistaken for an invalid
WebSocket message.

Any non-normal gateway close after `ready` is a relay failure. This includes
close status `1013` with reason `output_backpressure`. The helper cancels its
stdin writer, closes local stdout immediately so the parent OpenSSH process
observes EOF, and exits non-zero without waiting for another local stdin byte.
