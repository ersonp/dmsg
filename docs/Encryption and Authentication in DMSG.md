# Encryption and Authentication in DMSG

## Local Visor

While dialing a stream in order to connect to a remote client we do stream handshake with 
```
// Do stream handshake.
req, err := dStr.writeRequest(dst)
if err != nil {
	return nil, err
}
```
in [DialStream](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/client_session.go#L31) . [dStr.writeRequest](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L62) contains all the code for the handshake.

### Prepare fields
We set up the protocals required for encryption and authentication inside `dStr.writeRequest`  with 
```
// Prepare fields
s.prepareFields(true, Addr{PK: s.ses.LocalPK(), Port: lPort}, rAddr)
```

#### prepareFields
In [prepareFields](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L161)  a new Noise is created (Noise handles the handshake and the frame's cryptography).
```
ns, err := noise.New(noise.HandshakeKK, noise.Config{
	LocalPK: s.ses.LocalPK(),
	LocalSK: s.ses.localSK(),
	RemotePK: rAddr.PK,
	Initiator: init,
})
```

##### HandshakeKK
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

##### Noise
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

##### HandshakeState
We create a new [noise.HandshakeState](https://github.com/skycoin/noise/blob/master/state.go#L205) with this Noise config
```
hs, err := noise.NewHandshakeState(nc)
if err != nil {
	return nil, err
}
```
A `HandshakeState` tracks the state of a Noise handshake. As mentioned above in [HandshakeKK](#####HandshakeKK) the `messages` field in `HandshakePattern` has a list of two `MessagePattern`. So that means that the local visor (initiator) creates and sends these messages `{MessagePatternE, MessagePatternDHES, MessagePatternDHSS}` and in response receives the same massages from the remote. Then it creates and sends the second set `{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE}` and receives the same from the remote visor. This is tracked via [msgIdx](https://github.com/skycoin/noise/blob/master/state.go#L215) in `HandshakeState`

### Prepare request
After all the protocals are prepared we generate the handhsake message inside `dStr.writeRequest` with

#### MakeHandshakeMessage
```
// Prepare request.
var nsMsg []byte
if nsMsg, err = s.ns.MakeHandshakeMessage(); err != nil {
	return
}
```

in [s.ns.MakeHandshakeMessage](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/noise.go#L103) which uses [WriteMessage](https://github.com/skycoin/noise/blob/master/state.go#L332) method from the previously created `HandshakeState`.
```
// MakeHandshakeMessage generates handshake message for a current handshake state.
func (ns *Noise) MakeHandshakeMessage() (res []byte, err error) {
	if ns.hs.MessageIndex() < len(ns.pattern.Messages)-1 {
		res, _, _, err = ns.hs.WriteMessage(nil, nil)
		return
	} 
	res, ns.dec, ns.enc, err = ns.hs.WriteMessage(nil, nil)
	return res, err
}
```

##### WriteMessage
In this `WriteMessage`  method the noise messages required to do a handshake of type [HandshakeKK](###HandshakeKK). `res, _, _, err = ns.hs.WriteMessage(nil, nil)` this is used and no `CipherState` are generated as this is just the first handshake. . 
Here we are not passing a `payload` or `out` which are the parameters of `WriteMessage`. Both are passed as `nil`.
This is the first sequence of message in `msgIdx`.
The local visor is the initiator.

###### Local Write Message Handshake
Here as mentioned in [HandshakeKK](###HandshakeKK) the first message pattern is used tracked with `msgIdx`:
- [MessagePatternE](https://github.com/skycoin/noise/blob/master/state.go#L345)
	- Here a local ephemeral keypair is generated using [GenerateKeypair](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L15) method of `Secp256k1{}`
	- then the public key from the ephemeral keypair is appended to `out`
	- the it is also used in the method `s.ss.MixHash`  of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) which is used to create the two `CipherStates` later.
```
e, err := s.ss.cs.GenerateKeypair(s.rng)
if err != nil {
	return nil, nil, nil, err
}
s.e = e
out = append(out, s.e.Public...)
s.ss.MixHash(s.e.Public)
```
- [MessagePatternDHES](https://github.com/skycoin/noise/blob/master/state.go#L363)
	- If it is the initiator it creates a DH with the `s.e.Private` (local ephemeral Private key) and `s.rs` (remote party's static public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher` 
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` later.
```
s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs))
```
- [MessagePatternDHSS](https://github.com/skycoin/noise/blob/master/state.go#L375)
	- Creates a DH with the `s.s.Private` (local static Private key) and `s.rs` (remote party's static public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher`
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` later.
```
s.ss.MixKey(s.ss.cs.DH(s.s.Private, s.rs))
```

The output and payload is encrypted and hashed together to create a `out` with [s.ss.EncryptAndHash](https://github.com/skycoin/noise/blob/master/state.go#L123) of `symmetricState`
```
out = s.ss.EncryptAndHash(out, payload)
```

#### MakeSignedStreamRequest
After the Noise Handshake Messages is generated we create an object that is sent to the remote peer with [MakeSignedStreamRequest](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/types.go#L104) which takes in the parameters `StreamResponse` and `cipher.SecKey` local static Private key.
```
req = StreamRequest{
	Timestamp: time.Now().UnixNano(),
	SrcAddr: s.lAddr,
	DstAddr: s.rAddr,
	NoiseMsg: nsMsg,
}

obj := MakeSignedStreamRequest(&req, s.ses.localSK())
```

### Write request
The request object is then written to the stream with 
```
// Write request.
err = s.ses.writeObject(s.yStr, obj)
```
and awaits the response from the remote peer.

## Remote Visor
To accept the incoming stream we do the handshake with first [readRequest](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L90) which reads the Noise message from the initiator from the request and then generates a Noise message of it's own and sends it with [writeResponse](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L115)
```
// Do stream handshake.
req, err := dStr.readRequest()
if err != nil {
	return nil, err
}
if err = dStr.writeResponse(req.raw.Hash()); err != nil {
	return nil, err
}
```
in [acceptStream](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/client_session.go#L99).

### readRequest
We read the incoming request from the local visor (initator) via stream.

#### Prepare fields
We set up the protocals required for encryption and authentication inside `dStr.readRequest`  with 
```
// Prepare fields.
s.prepareFields(false, req.DstAddr, req.SrcAddr)
```

##### prepareFields
In [prepareFields](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L161)  a new Noise is created (Noise handles the handshake and the frame's cryptography). Everything here is the same as local visor's [prepareFields](####prepareFields) except the first paramater `init` which is `false` here.

#### Process Handshake
We proces the noise handshake message received from the request from local visor with [ProcessHandshakeMessage](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/noise.go#L114).
```
if err = s.ns.ProcessHandshakeMessage(req.NoiseMsg); err != nil {
	return
}
```

it contains [ReadMessage](https://github.com/skycoin/noise/blob/master/state.go#L401) method from the previously created `HandshakeState` in [prepareFields](#prepareFields).
```
// ProcessHandshakeMessage processes a received handshake message and appends the payload.
func (ns *Noise) ProcessHandshakeMessage(msg []byte) (err error) {
if ns.hs.MessageIndex() < len(ns.pattern.Messages)-1 {
	_, _, _, err = ns.hs.ReadMessage(nil, msg)
	return
} 
_, ns.enc, ns.dec, err = ns.hs.ReadMessage(nil, msg)
return err
}
```

##### ReadMessage
In this `ReadMessage`  method the noise messages required to do a handshake of type [HandshakeKK](###HandshakeKK).  The handshake messages are generated with the help of the `NoiseMsg` received from the request from the local visor (initiator).
`_, _, _, err = ns.hs.ReadMessage(nil, msg)` which is used and no `CipherState` are generated as this is just the first handshake. 
Here we are not passing a `out` but we pass the  `NoiseMsg` received from the request in the `message` parameter.
This is the first sequence of message in `msgIdx`.
The remote visor is not the initiator.

###### Remote Read Message Handshake
Here as mentioned in [HandshakeKK](###HandshakeKK) the first message pattern is used tracked with `msgIdx`:
- [MessagePatternE](https://github.com/skycoin/noise/blob/master/state.go#L414)
	- check if the lenght of the Noise Message received is greater than what is expected
```
expected := s.ss.cs.DHLen()
if msg == MessagePatternS && s.ss.hasK {
	expected += 16
}
if len(message) < expected {
	return nil, nil, nil, ErrShortMessage
}
```
	
   - retrive the remote party's ephemeral public key from the noise message in `s.re` and save it in the `symmetricState` with `s.ss.MixKey(s.re)`

```
switch msg {
case MessagePatternE:
	if cap(s.re) < s.ss.cs.DHLen() {
		s.re = make([]byte, s.ss.cs.DHLen())
	}
	s.re = s.re[:s.ss.cs.DHLen()]
	copy(s.re, message)
	s.ss.MixHash(s.re)
	if len(s.psk) > 0 {
		s.ss.MixKey(s.re)
	}
}
if err != nil {
	s.ss.Rollback()
	return nil, nil, nil, err
}
message = message[expected:]
```
- [MessagePatternDHES](https://github.com/skycoin/noise/blob/master/state.go#L446)
	- Creates a `DH` with the `s.s.Private` (local static Private key) and `s.re` (remote party's ephemeral public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher` 
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` later.
```
s.ss.MixKey(s.ss.cs.DH(s.s.Private, s.re))
```
- [MessagePatternDHSS](https://github.com/skycoin/noise/blob/master/state.go#L458)
	- Creates a `DH` with the `s.s.Private` (local static Private key) and `s.rs` (remote party's static public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher` 
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` later.
```
s.ss.MixKey(s.ss.cs.DH(s.s.Private, s.rs))
```

The output and payload is decrypted and hashed together to create a `out` with [s.ss.DecryptAndHash](https://github.com/skycoin/noise/blob/master/state.go#L133) of `symmetricState`
```
out, err = s.ss.DecryptAndHash(out, message)
if err != nil {
	s.ss.Rollback()
	return nil, nil, nil, err
}
```

### writeResponse
After the remote visor reads the request from the local visor (initiator) it writes back a handshake response to it.

#### MakeHandshakeMessage
```
// Prepare and write response.
nsMsg, err := s.ns.MakeHandshakeMessage()
if err != nil {
	return err
}
```

in [s.ns.MakeHandshakeMessage](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/noise.go#L103) which uses [WriteMessage](https://github.com/skycoin/noise/blob/master/state.go#L332) method from the previously created `HandshakeState`.
```
// MakeHandshakeMessage generates handshake message for a current handshake state.
func (ns *Noise) MakeHandshakeMessage() (res []byte, err error) {
	if ns.hs.MessageIndex() < len(ns.pattern.Messages)-1 {
		res, _, _, err = ns.hs.WriteMessage(nil, nil)
		return
	} 
	res, ns.dec, ns.enc, err = ns.hs.WriteMessage(nil, nil)
	return res, err
}
```

##### WriteMessage
In this `WriteMessage`  method the noise messages required to do a handshake of type [HandshakeKK](###HandshakeKK). `res, ns.dec, ns.enc, err = ns.hs.WriteMessage(nil, nil)` this is used and two `CipherState` are generated as this is the second handshake message of remote. 
Here we are not passing a `payload` or `out` which are the parameters of `WriteMessage`. Both are passed as `nil`.
This is the second sequence of message in `msgIdx`.
The remote visor is not the initiator.

###### Remote Write Message Handshake
Here as mentioned in [HandshakeKK](###HandshakeKK) the second message pattern is used tracked with `msgIdx`:
- [MessagePatternE](https://github.com/skycoin/noise/blob/master/state.go#L345)
	- Here a local ephemeral keypair is generated using [GenerateKeypair](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L15) method of `Secp256k1{}`
	- then the public key from the ephemeral keypair is appended to `out`
	- the it is also used in the method `s.ss.MixHash`  of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) which is used to create the two `CipherStates` below.
```
e, err := s.ss.cs.GenerateKeypair(s.rng)
if err != nil {
	return nil, nil, nil, err
}
s.e = e
out = append(out, s.e.Public...)
s.ss.MixHash(s.e.Public)
```
- [MessagePatternDHEE](https://github.com/skycoin/noise/blob/master/state.go#L361)
	- Creates a `DH` with the `s.e.Private` (local ephemeral Private key) and `s.re` (remote party's ephemeral public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher` 
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` below.
```
s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.re))
```
- [MessagePatternDHSE](https://github.com/skycoin/noise/blob/master/state.go#L369)
	- Creates a DH with the `s.e.Private` (local ephemeral Private key) and `s.rs` (remote party's static public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher`
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` later.
```
s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs))
```

The output and payload is encrypted and hashed together to create a `out` with [s.ss.EncryptAndHash](https://github.com/skycoin/noise/blob/master/state.go#L123) of `symmetricState`
```
out = s.ss.EncryptAndHash(out, payload)
```

The two `CipherStates` are finally generated where one is used for encryption of messages to the initiator peer, the other is used for decryption of messages from the initiator peer.
The `ciperStates` are generated with [s.ss.Split](https://github.com/skycoin/noise/blob/master/state.go#L146)
```
cs1, cs2 := s.ss.Split()
```

## Local Visor

After writing the request the local visor awaits the response and reads it with [dStr.readResponse](https://github.com/skycoin/dmsg/blob/develop/pkg/dmsg/stream.go#L146)
```
if err := dStr.readResponse(req); err != nil {
	return nil, err
}
```

### readResponse
We read the incoming response to our request from the remote visor via stream.

#### Process Handshake
We proces the noise handshake message received from the response from remote visor with [ProcessHandshakeMessage](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/noise.go#L114).
```
s.ns.ProcessHandshakeMessage(resp.NoiseMsg)
```

it contains [ReadMessage](https://github.com/skycoin/noise/blob/master/state.go#L401) method from the previously created `HandshakeState` in [prepareFields](#prepareFields).
```
// ProcessHandshakeMessage processes a received handshake message and appends the payload.
func (ns *Noise) ProcessHandshakeMessage(msg []byte) (err error) {
if ns.hs.MessageIndex() < len(ns.pattern.Messages)-1 {
	_, _, _, err = ns.hs.ReadMessage(nil, msg)
	return
} 
_, ns.enc, ns.dec, err = ns.hs.ReadMessage(nil, msg)
return err
}
```

##### ReadMessage
In this `ReadMessage`  method the noise messages required to do a handshake of type [HandshakeKK](###HandshakeKK).  The handshake messages are generated with the help of the `NoiseMsg`  received from the response from the remote visor.
`_, ns.enc, ns.dec, err = ns.hs.ReadMessage(nil, msg)` which is used and two `CipherState` are generated as this is the second handshake. 
Here we are not passing a `out` but we pass the  `NoiseMsg` received from the response in the `message` parameter.
This is the second sequence of message in `msgIdx`.
The local visor is the initiator.

###### Local Read Message Handshake
Here as mentioned in [HandshakeKK](###HandshakeKK) the second message pattern is used tracked with `msgIdx`:
- [MessagePatternE](https://github.com/skycoin/noise/blob/master/state.go#L414)
	- check if the lenght of the Noise Message received is greater than what is expected
```
expected := s.ss.cs.DHLen()
if msg == MessagePatternS && s.ss.hasK {
	expected += 16
}
if len(message) < expected {
	return nil, nil, nil, ErrShortMessage
}
```
	
   - retrive the remote party's ephemeral public key from the noise message in `s.re` and save it in the `symmetricState` with `s.ss.MixKey(s.re)`

```
switch msg {
case MessagePatternE:
	if cap(s.re) < s.ss.cs.DHLen() {
		s.re = make([]byte, s.ss.cs.DHLen())
	}
	s.re = s.re[:s.ss.cs.DHLen()]
	copy(s.re, message)
	s.ss.MixHash(s.re)
	if len(s.psk) > 0 {
		s.ss.MixKey(s.re)
	}
}
if err != nil {
	s.ss.Rollback()
	return nil, nil, nil, err
}
message = message[expected:]
```
- [MessagePatternDHEE](https://github.com/skycoin/noise/blob/master/state.go#L444)
	- Creates a `DH` with the `s.e.Private` (local ephemeral Private key) and `s.re` (remote party's ephemeral public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher` 
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` below.
```
s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.re))
```
- [MessagePatternDHSE](https://github.com/skycoin/noise/blob/master/state.go#L452)
	- Creates a `DH` with the `s.s.Private` (local static Private key) and `s.re` (remote party's ephemeral public key) using the [DH](https://github.com/skycoin/dmsg/blob/develop/pkg/noise/dh.go#L24) method of `Secp256k1{}`
	- the `DH` method uses [cipher.MustECDH](https://github.com/skycoin/skycoin/blob/release/0.27.1/src/cipher/crypto.go#L299) from `github.com/skycoin/skycoin/src/cipher` 
	- `s.ss.MixKey` of [symmetricState](https://github.com/skycoin/noise/blob/master/state.go#L73) takes in the output from the `DH` method which is used to create the two `CipherStates` below.
```
s.ss.MixKey(s.ss.cs.DH(s.s.Private, s.re))
```

The output and payload is decrypted and hashed together to create a `out` with [s.ss.DecryptAndHash](https://github.com/skycoin/noise/blob/master/state.go#L133) of `symmetricState`
```
out, err = s.ss.DecryptAndHash(out, message)
if err != nil {
	s.ss.Rollback()
	return nil, nil, nil, err
}
```

The two `CipherStates` are finally generated where one is used for encryption of messages to the remote peer, the other is used for decryption of messages from the remote peer.
The `ciperStates` are generated with [s.ss.Split](https://github.com/skycoin/noise/blob/master/state.go#L146)
```
cs1, cs2 := s.ss.Split()
```