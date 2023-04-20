# Encryption and Authentication in DMSG

While dialing a stream in order to connect to a remote client we do stream handshake with 
```
// Do stream handshake.
req, err := dStr.writeRequest(dst)
if err != nil {
	return nil, err
}
```
in [DialStream](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/client_session.go#L31) .

## Prepare fields
We set up the protocals required for encryption and authentication inside `dStr.writeRequest`  with 
```
// Prepare fields.

s.prepareFields(true, Addr{PK: s.ses.LocalPK(), Port: lPort}, rAddr)
```
in [prepareFields](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L161)  a new Noise is created (Noise handles the handshake and the frame's cryptography).
```
ns, err := noise.New(noise.HandshakeKK, noise.Config{
	LocalPK: s.ses.LocalPK(),
	LocalSK: s.ses.localSK(),
	RemotePK: rAddr.PK,
	Initiator: init,
})
```

### HandshakeKK
We use the handshake type [HandshakeKK](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/net.go#L36) while creating the new Noise.
```
// HandshakeKK is the KK handshake pattern.
// legend: s(static) e(ephemeral)
// -> s
// <- s
// ...
// -> e, es, ss
// <- e, ee, se
HandshakeKK = noise.HandshakeKK
```
The `HandshakeKK` uses  [noise.HandshakeKK](https://github.com/skycoin/noise/blob/master/patterns.go#L29).
```
var HandshakeKK = HandshakePattern{
	Name: "KK",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
	{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
	{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}
```

### Noise
In [noise.New](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/noise.go#L50)  we create a config for `github.com/skycoin/noise` 
```
nc := noise.Config{
	CipherSuite: noise.NewCipherSuite(Secp256k1{}, noise.CipherChaChaPoly, noise.HashSHA256),
	Random: rand.Reader,
	Pattern: pattern,
	Initiator: config.Initiator,
	StaticKeypair: noise.DHKey{
		Public: config.LocalPK[:],
		Private: config.LocalSK[:],
	},
}
```
where the `CipherSuite` is created from [noise.NewCipherSuite](https://github.com/skycoin/noise/blob/master/cipher_suite.go#L84) and is provided with `noise.DHFunc`, `noise.CipherFunc`, `noise.HashFunc`
- [Secp256k1](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go) is used for `noise.DHFunc`
- [noise.CipherChaChaPoly](https://github.com/skycoin/noise/blob/master/cipher_suite.go#L161) is used for `noise.CipherFunc` 
- [noise.HashSHA256](https://github.com/skycoin/noise/blob/master/cipher_suite.go#L200) is used for `noise.HashFunc`

then we create a new `HandshakeState` with this Noise config
```
hs, err := noise.NewHandshakeState(nc)
if err != nil {
	return nil, err
}
```

## Prepare request
After all the protocals are prepared we generate the handhsake message inside `dStr.writeRequest` with

### MakeHandshakeMessage
```
// Prepare request.
var nsMsg []byte
if nsMsg, err = s.ns.MakeHandshakeMessage(); err != nil {
	return
}
```

in [s.ns.MakeHandshakeMessage](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/noise.go#L103) which uses [WriteMessage](https://github.com/skycoin/noise/blob/master/state.go#L332) method from the previously created `HandshakeState`.

### WriteMessage
In this `WriteMessage`  method the noise messages required to do a handshake of type [HandshakeKK](###HandshakeKK) are generated along side two `CipherStates`. One is used for encryption of messages to the remote peer, the other is used for decryption of messages from the remote peer.

Here as mentioned in [HandshakeKK](###HandshakeKK) the message pattern used by the initiator are
- [MessagePatternE](https://github.com/skycoin/noise/blob/master/state.go#L345)
	Here a local ephemeral keypair is generated using [GenerateKeypair](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L15) method of `Secp256k1{}`
```
e, err := s.ss.cs.GenerateKeypair(s.rng)
if err != nil {
	return nil, nil, nil, err
}
```
- [MessagePatternDHES](https://github.com/skycoin/noise/blob/master/state.go#L363)
	- Creates a DH with the `s.e.Private` (local ephemeral Private key) and `s.rs` (remote party's static public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH]() from 
```
s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs))	
```
- [MessagePatternDHSS](https://github.com/skycoin/noise/blob/master/state.go#L375)