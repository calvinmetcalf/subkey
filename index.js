'use strict';
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
var inherits = require('util').inherits;
var EE = require('events').EventEmitter;
var privCache = {};
var pubCache = {};

function hash(msg) {
  return crypto.createHash('sha224').update(msg).digest();
}

function getPrivate(key, async) {
  var id;
  if (key && !Buffer.isBuffer(key) && typeof key !== 'string') {
    if (key.key && (Buffer.isBuffer(key.key) || typeof key.key === 'string')) {
      id = id = hash(key.key).toString('hex');
    } else {
      throw new TypeError('invalid key');
    }
  } else {
    id = hash(key).toString('hex');
  }
  if (async) {
    id += 'async';
  }
  if (id in privCache) {
    return privCache[id];
  }
  return privCache[id] = new Signer(key, async); // eslint-disable-line no-return-assign
}

function getPublic(key, sig, insecure) {
  var id = hash(Buffer.concat([key, sig.key, sig.keysig])).toString('hex');
  if (insecure) {
    id += 'insecure';
  }
  if (id in pubCache) {
    return pubCache[id];
  }
  return pubCache[id] = new Verifier(key, sig.key, sig.keysig, insecure); // eslint-disable-line no-return-assign
}
inherits(Signer, EE);
function Signer(key, async) {
  EE.call(this);
  this.pub = null;
  this.ec = null;
  this.sig = null;
  this.async = async;
  this.createPair(key);
}
Signer.prototype.createPair = function (key) {
  this.ec = ec.genKeyPair();
  this.pub = new Buffer(this.ec.getPublic(true, 'hex'), 'hex');
  if (this.async) {
    var self = this;
    return this.async(key, this.pub, function (err, sig){
      if (err) {
        self.err = err;
        return self.emit('error', err);
      } else {
        self.sig = sig;
        return self.emit('ready');
      }
    });
  }
  this.sig = crypto.createSign('RSA-SHA224').update(this.pub).sign(key);
};

Signer.prototype.sign = function (msg, cb) {
  if (this.async) {
    return this.signAsync(msg, cb);
  } else {
    return this._sign(msg);
  }
};
Signer.prototype._sign = function (msg) {
  var sig = new Buffer(this.ec.sign(hash(msg)).toDER());
  return messages.sig.encode({
    key: this.pub,
    keysig: this.sig,
    sig: sig
  });
};
Signer.prototype.signAsync = function (msg, cb) {
  var self = this;
  if (this.err) {
    return process.nextTick(function () {
      cb(self.err);
    });
  }
  if (this.sig) {
    return process.nextTick(function () {
      cb(null, self._sign(msg));
    });
  }
  function onerr(e) {
    self.removeListener('ready', onsuccess);
    cb(e);
  }
  function onsuccess() {
    self.removeListener('error', onerr);
    cb(null, self._sign(msg));
  }
  this.on('error', onerr);
  this.on('ready', onsuccess);
};
function Verifier (key, derivedKey, keySig, insecure) {
  this.ec = null;
  this.insecure = !!insecure;
  this.verifySig(key, derivedKey, keySig);
  this.setupEc(derivedKey);
}
Verifier.prototype.setupEc = function(derivedKey) {
  this.ec = ec.keyFromPublic(derivedKey.toString('hex'), 'hex');
};
Verifier.prototype.verifySig = function(key, derivedKey, keySig) {
  if (!crypto.createVerify(this.insecure ? 'RSA-SHA1' : 'RSA-SHA224').update(derivedKey).verify(key, keySig)) {
    throw new Error('unable to verify derived key');
  }
};
Verifier.prototype.verify = function (sig, message) {
  if (!this.ec.verify(hash(message).toString('hex'), sig)) {
    throw new Error('unable to verify message');
  }
  return true;
};
exports.signAsync = function (id, message, sign, cb) {
  return getPrivate(id, sign).sign(message, cb);
};
exports.sign = function (key, message) {
  return getPrivate(key).sign(message);
};
exports.clearKeys = function () {
  privCache = {};
  pubCache = {};
};
exports.verify = function (key, _sig, message) {
  try {
    var sig = messages.sig.decode(_sig);
    return getPublic(key, sig).verify(sig.sig, message);
  } catch (_) {
    return false;
  }
};

exports.verifyAsync = function (key, _sig, message, callback) {
  try {
    var sig = messages.sig.decode(_sig);
    var out = getPublic(key, sig, true).verify(sig.sig, message);
    process.nextTick(function () {
      callback(null, out);
    });
  } catch (_) {
    process.nextTick(function () {
      callback(null, false);
    });
  }
};
