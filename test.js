/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {hd} = require('bcoin');
const {BID, Challenge, Response} = require('./bid');

describe('BID', function() {
  // Test vectors from
  // https://github.com/trezor/trezor-firmware/
  //   blob/master/tests/device_tests/test_msg_signidentity.py
  const mnemonic =
    'alcohol woman abuse must during monitor ' +
    'noble actual mixed trade anger aisle';
  const address = '17F17smBTX9VTZA9Mj8LM5QGYNZnmziCjL';
  const publicKey =
    '023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45';
  const signature =
    '20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb4' +
     '1770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02';
  const identity = 'https://satoshi@bitcoin.org/login';
  let bid, challenge;

  it('should construct client bid', () => {
    bid = new BID({
      identity,
      mnemonic
    });

    assert.strictEqual(bid.identity, identity);
    assert.strictEqual(bid.mnemonic, mnemonic);
    assert(bid.master);
    assert(bid.master instanceof hd.HDPrivateKey);
  });

  it('should hash identity', () => {
    const hash = bid.getIdentityHash();

    assert.bufferEqual(hash, Buffer.from(
      'd0e2389d4c8394a9f3e32de01104bf6e8db2d9e2bb0905d60fffa5a18fd696db',
      'hex'));
  });

  it('should derive path from hash', () => {
    const path = bid.getPath();

    assert.strictEqual(path,
      'm/2147483661/2637750992/2845082444/3761103859/4005495825');
  });

  it('should derive public key from path', () => {
    const pubKey = bid.getPublicKey();

    assert.strictEqual(pubKey.toString('hex'), publicKey);
  });

  it('should derive address from public key', () => {
    const addr = bid.getAddress();

    assert.strictEqual(addr, address);
  });

  it('should create a challenge', () => {
    challenge = new Challenge({
      hidden:
        'cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2',
      visual: '2015-03-23 17:39:22'
    });

    assert(Buffer.isBuffer(challenge.sigHash));
    assert.strictEqual(challenge.sigHash.length, 32);
  });

  it('should sign challenge with derived key', () => {
    const sig = bid.signChallenge(challenge);

    assert.strictEqual(sig.toString('hex'), signature);
  });

  it('should verify challenge with given address', () => {
    const response = new Response({
      address,
      publicKey,
      signature
    });

    // Server-side BID
    const bid2 = new BID({
      publicKey
    });

    assert(bid2.verifyResponse(challenge, response));
  });
});
