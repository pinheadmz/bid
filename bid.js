/*!
 * bid.js - User auth with Bitcoin message signing for bcoin
 * Copyright (c) 2018, Matthew Zipkin (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {hd, KeyRing} = require('bcoin');
const bufio = require('bufio');
const assert = require('bsert');
const sha256 = require('bcrypto/lib/sha256');
const secp256k1 = require('bcrypto/lib/secp256k1');
const {safeEqual} = require('bcrypto/lib/safe');

class BID {
  constructor(options) {
    this.mnemonic = null;
    this.master = null;
    this.publicKey = null;
    this.privateKey = null;
    this.address = null;
    this.identity = null;
    this.challengeHidden = null;
    this.challengeVisual = null;
    this.index = 0;

    this._identityHash = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (options.identity != null) {
      assert(typeof options.identity === 'string', 'Identity must be string');
      this.identity = options.identity;
    }

    if (options.mnemonic != null) {
      assert(typeof options.mnemonic === 'string', 'Mnemonic must be string');
      this.mnemonic = options.mnemonic;
      const mne = hd.Mnemonic.fromPhrase(this.mnemonic);
      this.master = hd.fromMnemonic(mne);
    }

    if (options.publicKey != null) {
      if (!Buffer.isBuffer(options.publicKey))
        options.publicKey = Buffer.from(options.publicKey, 'hex');
      assert(options.publicKey.byteLength === 33,
        'Public key must be 33 bytes');
      this.publicKey = options.publicKey;
    }

    return this;
  }

  getIdentityHash() {
    if (!this._identityHash) {
      assert(typeof this.index === 'number', 'Identity index must be a number');
      assert(typeof this.identity === 'string', 'Identity must be a string');

      const bw = bufio.write();
      bw.writeU32(this.index);
      bw.writeString(this.identity, 'utf8');

      this._identityHash = sha256.digest(bw.render());
    }

    return this._identityHash;
  }

  getPath() {
    const hash = this.getIdentityHash();

    assert(Buffer.isBuffer(hash), 'Identity hash must be buffer');
    assert(hash.byteLength === 32, 'Identity hash must be 32 bytes');

    // Ensure all values are BIP32 hardened, unsigned ints
    const purpose = (13 | 0x80000000) >>> 0;
    const A = (hash.readUInt32LE(0) | 0x80000000) >>> 0;
    const B = (hash.readUInt32LE(4) | 0x80000000) >>> 0;
    const C = (hash.readUInt32LE(8) | 0x80000000) >>> 0;
    const D = (hash.readUInt32LE(12) | 0x80000000) >>> 0;

    return `m/${purpose}/${A}/${B}/${C}/${D}`;
  }

  getPrivateKey() {
    if (!this.privateKey) {
      assert (this.master, 'Master key required to derive private key');

      const path = this.getPath();
      this.privateKey = this.master.derivePath(path).privateKey;
    }

    return this.privateKey;
  }

  getPublicKey() {
    if (!this.publicKey) {
      assert(this.master, 'Master key required to derive public key');

      const path = this.getPath();
      this.publicKey = this.master.derivePath(path).toPublic().publicKey;
    }

    return this.publicKey;
  }

  getAddress() {
    if (!this.address) {
      const pub = this.getPublicKey();
      const ring = KeyRing.fromPublic(pub);
      this.address = ring.getAddress();
    }

    return this.address.toString();
  }

  signChallenge(challenge) {
    const pub = this.getPublicKey();
    const prv = this.getPrivateKey();

    assert(Buffer.isBuffer(pub), 'Public key must be a buffer');
    assert(Buffer.isBuffer(prv), 'Private key must be a buffer');
    assert(Buffer.isBuffer(challenge.sigHash), 'sigHash key must be a buffer');
    assert(pub.byteLength === 33, 'Public key must be 33 bytes');
    assert(prv.byteLength === 32, 'Private key must be 32 bytes');
    assert(challenge.sigHash.byteLength === 32, 'sigHash must be 32 bytes');

    const compress = 0x04 !== pub.readInt8(0);
    const [s, r] =
      secp256k1.signRecoverable(challenge.sigHash, prv);

    const bw = bufio.write();

    bw.writeI8(r + 27 + (compress ? 4 : 0));
    bw.writeBytes(s);

    return bw.render();
  }

  verifyResponse(challenge, response) {
    // Sanity check
    const addr = this.getAddress();
    assert(addr === response.address, 'Public key and address do not match');

    assert(response.signature.length === 130, 'Bad signature length');

    const sig = Buffer.from(response.signature, 'hex');
    const pubKey = Buffer.from(response.publicKey, 'hex');

    const flagByte = sig.readUInt8(0) - 27;
    assert(flagByte < 8, 'Invalid flag byte');

    const compressed = Boolean(flagByte & 4);
    const recovery = flagByte & 3;

    const key = secp256k1.recover(
      challenge.sigHash,
      sig.slice(1),
      recovery,
      compressed);

    assert(key, 'Unrecoverable public key');

    return safeEqual(key, pubKey) === 1;
  }
}

class Challenge {
  constructor(options) {
    if (!Buffer.isBuffer(options.hidden))
      this.hidden = Buffer.from(options.hidden, 'hex');
    else
      this.hidden = options.hidden;
    assert(this.hidden.byteLength === 32,
      'Hidden string must be 32 bytes');

    assert(typeof options.visual === 'string',
      'Visual challenge must be string');
    this.visual = Buffer.from(options.visual, 'utf8');

    const data = bufio.write();
    data.writeHash(sha256.digest(this.hidden));
    data.writeHash(sha256.digest(this.visual));

    const prefix = 'Bitcoin Signed Message:\n';
    const msg = bufio.write();
    msg.writeVarString(prefix);
    msg.writeVarBytes(data.render());

    this.sigHash = sha256.digest(sha256.digest(msg.render()));
  }
}

class Response {
  constructor(options) {
    assert(typeof options.address === 'string', 'Address required');

    if (!Buffer.isBuffer(options.publicKey))
      options.publicKey = Buffer.from(options.publicKey, 'hex');
    assert(options.publicKey.byteLength === 33,
      'Public key must be 33 bytes');

    if (!Buffer.isBuffer(options.signature))
      options.signature = Buffer.from(options.signature, 'hex');
    assert(options.signature.byteLength === 65,
      'Signature must be 65 bytes');

    this.address = options.address;
    this.publicKey = options.publicKey.toString('hex');
    this.signature = options.signature.toString('hex');
  }
}

/*
 * Expose
 */

module.exports = {
  BID,
  Challenge,
  Response
};
