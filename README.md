Implementation of
[SLIP-13](https://github.com/satoshilabs/slips/blob/master/slip-0013.md)
for use with bcoin.

### Installation

[`bcoin`](https://github.com/bcoin-org/bcoin) is added as a peer dependency, this package assumes bcoin is installed
globally and requireable. Besides that:

```
git clone https://github.com/pinheadmz/bid
cd bid
npm i
```

```js
const {BID, Challenge, Response} = require('bid');
```

### Protocol

1. Client requests login challenge:

```
GET https://purse.io/loginchallenge
```

2. Server generates a challenge consisting of a 32-byte random string and a
"visual" string for the user to "ok":

```js
const challenge = new Challenge({
  hidden: 'cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2',
  visual: '2015-03-23 17:39:22'
});
```

3. Client derives a key from its wallet seed based on the URI, and signs the
challenge:

```js
const bid = new BID({
  identity: 'https://purse.io/loginchallenge',
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
});

const sig = bid.signChallenge(challenge)
```

4. Client constructs a response and sends it to the server:

```js
const response = new Response({
  address: bid.getAddress(),
  publicKey: bid.getPublicKey(),
  signature: sig
});
```

```
PUT https://purse.io/loginchallenge --data <reponse as JSON>
```

5. Server verifies the response:

```js
const bid2 = new BID({
  publicKey: response.publicKey
});

return bid2.verifyResponse(challenge, response); // true
```

6. If the response is verified `true`, server proceeds in one of two ways:

- publicKey is recognized -> user account is logged in

- publicKey is NOT recognized -> new user account is created, and logged in
