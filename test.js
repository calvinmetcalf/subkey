'use strict';
var test = require('tape');
var subkey = require('./');
var fs = require('fs');
var privkey = fs.readFileSync('./privkey.pem');
var pubkey = fs.readFileSync('./pubkey.pem');
var privkey2 = fs.readFileSync('./privkey2.pem');
var pubkey2 = fs.readFileSync('./pubkey2.pem');
var crypto = require('crypto');
var privpassword = {
  key: fs.readFileSync('./privpassword.pem'),
  passphrase: 'password'
};
var pubpassword = fs.readFileSync('./pubpassword.pem');
var crypto = require('crypto');
test('basic', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privkey, msg);
  t.ok(sig, 'produce sig');
  t.ok(subkey.verify(pubkey, sig, msg), 'verify it');
});
test('basic with other key', function (t) {
  t.plan(2);
  var msg = 'other';
  var sig = subkey.sign(privkey2, msg);
  t.ok(sig, 'produce sig');
  t.ok(subkey.verify(pubkey2, sig, msg), 'verify it');
});
test('basic with password', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privpassword, msg);
  t.ok(sig, 'produce sig');
  t.ok(subkey.verify(pubpassword, sig, msg), 'verify it');
});
test('fail', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privkey, msg);
  t.ok(sig, 'produce sig');
  t.notok(subkey.verify(pubkey, sig, 'basics'), 'don\'t verify it');
});
test('fail with wrong key', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privkey, msg);
  t.ok(sig, 'produce sig');
  t.notok(subkey.verify(pubkey2, sig, 'basics'), 'don\'t verify it');
});
function makeTest(i) {
  test('random round ' + i, function (t) {
    t.plan(2);
    var msg = crypto.randomBytes(16);
    var sig = subkey.sign(privkey, msg);
    t.ok(sig, 'produce sig');
    t.ok(subkey.verify(pubkey, sig, msg), 'verify it');
  });
  test('random round ' + i + ' with other key', function (t) {
    t.plan(2);
    var msg = crypto.randomBytes(16);
    var sig = subkey.sign(privkey2, msg);
    t.ok(sig, 'produce sig');
    t.ok(subkey.verify(pubkey2, sig, msg), 'verify it');
  });
  test('random round ' + i + ' with password', function (t) {
    t.plan(2);
    var msg = crypto.randomBytes(16);
    var sig = subkey.sign(privpassword, msg);
    t.ok(sig, 'produce sig');
    t.ok(subkey.verify(pubpassword, sig, msg), 'verify it');
  });
}
var i = 0;
while (++i < 20) {
  makeTest(i);
}
function signIt(key, msg, callback) {
  process.nextTick(function () {
    callback(null, crypto.createSign('RSA-SHA1').update(msg).sign(key));
  });
}
test('basic async', function (t) {
  t.plan(2);
  var msg = 'basic';
  subkey.signAsync(privkey, msg, signIt, function (err, sig) {
    t.ok(sig, 'produce sig');
    subkey.verifyAsync(pubkey, sig, msg, function (err, valid) {
      t.ok(valid, 'verify it');
    });
  });
});
test('basic with other key', function (t) {
  t.plan(2);
  var msg = 'basic';
  subkey.signAsync(privkey2, msg, signIt, function (err, sig) {
    t.ok(sig, 'produce sig');
    subkey.verifyAsync(pubkey2, sig, msg, function (err, valid) {
      t.ok(valid, 'verify it');
    });
  });
});
test('basic async with password', function (t) {
  t.plan(2);
  var msg = 'basic';
  subkey.signAsync(privpassword, msg, signIt, function (err, sig) {
    t.ok(sig, 'produce sig');
    subkey.verifyAsync(pubpassword, sig, msg, function (err, valid) {
      t.ok(valid, 'verify it');
    });
  });
});
test('fail async', function (t) {
  t.plan(2);
  var msg = 'basic';
  subkey.signAsync(privkey, msg, signIt, function (err, sig) {
    t.ok(sig, 'produce sig');
    subkey.verifyAsync(pubkey, sig, 'basics', function (err, valid) {
      t.notok(valid, 'verify it');
    });
  });
});
test('fail async with wrong key', function (t) {
  t.plan(2);
  var msg = 'basic';
  subkey.signAsync(privkey, msg, signIt, function (err, sig) {
    t.ok(sig, 'produce sig');
    subkey.verifyAsync(pubkey2, sig, msg, function (err, valid) {
      t.notok(valid, 'verify it');
    });
  });
});
test('fail if async is mixed with sync', function (t) {
  t.plan(2);
  var msg = 'basic';
  subkey.signAsync(privkey, msg, signIt, function (err, sig) {
    t.ok(sig, 'produce sig');
    t.notok(subkey.verify(pubkey, sig, msg), 'verify it');
  });
});
test('fail if async is mixed with sync other way', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privkey, msg);
  t.ok(sig, 'produce sig');
  subkey.verifyAsync(pubkey, sig, msg, function (err, valid) {
    t.notok(valid, 'verify it');
  });
});
