var protobuf = require('protocol-buffers');
var EC = require('elliptic').ec;
var ec = new EC('ed25519');
var messages = protobuf([
  'message sig {',
   'required bytes key = 1;',
   'required bytes keysig = 2;',
   'required bytes sig = 3;',
  '}'
].join('\n'));
var crypto = require('crypto');

var privCache = {};
var pubCache = {};

function hash(msg) {
  return crypto.createHash('sha224').update(msg).digest();
}

function getPrivate(key) {
  var id = hash(key).toString('hex');
  if (id in privCache) {
    return privCache[id];
  }
  return privCache[id] = new Signer(key);
}

function getPublic(key, sig) {
  var id = hash(Buffer.concat([key, sig.key, sig.keysig])).toString('hex');
  if (id in pubCache) {
    return pubCache[id];
  }
  return pubCache[id] = new Verifier(key, sig.key, sig.keysig);
}
function Signer(key) {
  this.pub = null;
  this.ec = null;
  this.sig = null;
  this.createPair(key);
}
Signer.prototype.createPair = function (key) {
  this.ec = ec.genKeyPair();
  this.pub = new Buffer(this.ec.getPublic(true, 'hex'), 'hex');
  this.sig = crypto.createSign('RSA-SHA224').update(this.pub).sign(key);
}

Signer.prototype.sign = function (msg) {
  var sig = new Buffer(this.ec.sign(hash(msg)).toDER());
  return messages.sig.encode({
    key: this.pub,
    keysig: this.sig,
    sig: sig
  });
}
function Verifier (key, derivedKey, keySig) {
  this.ec = null;
  this.verifySig(key, derivedKey, keySig);
  this.setupEc(derivedKey);
}
Verifier.prototype.setupEc = function(derivedKey) {
  this.ec = ec.keyFromPublic(derivedKey.toString('hex'), 'hex')
}
Verifier.prototype.verifySig = function(key, derivedKey, keySig) {
  if (!crypto.createVerify('RSA-SHA224').update(derivedKey).verify(key, keySig)) {
      throw new Error('unable to verify derived key');
  }
}
Verifier.prototype.verify = function (sig, message) {
  if (!this.ec.verify(hash(message).toString('hex'), sig)) {
      throw new Error('unable to verify message');
  }
  return true;
}
exports.sign = function (key, message) {
  return getPrivate(key).sign(message);
}
exports.clearKeys = function () {
  privCache = {};
  pubCache = {};
};
exports.verify = function (key, _sig, message) {
  var sig = messages.sig.decode(_sig);
  return getPublic(key, sig).verify(sig.sig, message);
}
