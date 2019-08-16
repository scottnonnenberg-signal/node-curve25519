var crypto = require('crypto');
var binding = require("bindings")("curve");

var BASEPOINT = (function() {
  var buf = new Buffer(32);
  buf[0] = 9;
  for (var i=1; i<32; i++) {
    buf[i] = 0;
  }
  return buf;
})();

function makeSecretKey(key) {
  if (!(key instanceof Buffer)) {
    throw 'key must be a Buffer';
  }
  if (key.length !== 32) {
    throw 'key must be 32 bytes long';
  }

  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;

  return key;
}

// The core native interface

function keyPair(privKey) {
  var priv = makeSecretKey(privKey);

  var pubKey = new Buffer(32);

  // The return value is just 0, the operation is done in place
  var err = binding.donna(pubKey,
                          privKey,
                          BASEPOINT);

  return { pubKey, privKey };
}

function sharedSecret(pubKey, privKey) {
  // Where to store the result
  var sharedKey = new Buffer(32);

  // The return value is just 0, the operation is done in place
  var err = binding.donna(sharedKey,
                          privKey,
                          pubKey);

  return sharedKey;
}

function sign(privKey, message) {
  // Where to store the result
  var signature = new Buffer(64);

  var err = binding.sign(signature,
                         privKey,
                         message,
                         message.length);

  return signature;
}

function verify(pubKey, message, signature) {
  var res = binding.verify(signature,
                           pubKey,
                           message,
                           message.length);

  return res !== 0;
}

// Helper functions

function validatePrivKey(privKey) {
  if (privKey === undefined || !(privKey instanceof Buffer) || privKey.length !== 32) {
    throw new Error("Invalid private key");
  }
}

function validatePubKeyFormat(pubKey) {
  if (pubKey === undefined || ((pubKey.length !== 33 || pubKey[0] !== 5) && pubKey.length !== 32)) {
    throw new Error("Invalid public key");
  }
  if (pubKey.length === 33) {
    return pubKey.slice(1);
  }

  return pubKey;
}

function processKeys(rawKeys) {
  // Prepend version byte
  var origPub = new Uint8Array(rawKeys.pubKey);
  var pub = new Uint8Array(33);
  pub.set(origPub, 1);
  pub[0] = 5;

  return { pubKey: Buffer.from(pub), privKey: rawKeys.privKey };
}

// Public API

exports.generateKeyPair = function() {
  var privKey = crypto.randomBytes(32);

  return exports.createKeyPair(privKey);
}

exports.createKeyPair = function(privKey) {
  validatePrivKey(privKey);

  var rawKeys = keyPair(privKey);

  return processKeys(rawKeys);
}

exports.calculateAgreement = function(pubKey, privKey) {
  pubKey = validatePubKeyFormat(pubKey);

  validatePrivKey(privKey);

  if (pubKey === undefined || pubKey.length !== 32) {
    throw new Error("Invalid public key");
  }

  return sharedSecret(pubKey, privKey);
}

exports.verifySignature = function(pubKey, msg, sig) {
  pubKey = validatePubKeyFormat(pubKey);

  if (pubKey === undefined || pubKey.length !== 32) {
    throw new Error("Invalid public key");
  }

  if (msg === undefined) {
    throw new Error("Invalid message");
  }

  if (sig === undefined || sig.length !== 64) {
    throw new Error("Invalid signature");
  }

  return verify(pubKey, msg, sig);
}

exports.calculateSignature = function(privKey, message) {
  validatePrivKey(privKey);

  if (message === undefined) {
    throw new Error("Invalid message");
  }

  return sign(privKey, message);
}

exports.validatePubKeyFormat = function(buffer) {
  return validatePubKeyFormat(buffer);
}

exports.makeSecretKey = function(buffer) {
  return makeSecretKey(buffer);
}
