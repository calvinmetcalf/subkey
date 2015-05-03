var test = require('tape');
var subkey = require('./');
var fs = require('fs');
var privkey = fs.readFileSync('./privkey.pem');
var pubkey = fs.readFileSync('./pubkey.pem');
test('basic', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privkey, msg);
  t.ok(sig, 'produce sig');
  t.ok(subkey.verify(pubkey, sig, msg), 'verify it');
});
test('fail', function (t) {
  t.plan(2);
  var msg = 'basic';
  var sig = subkey.sign(privkey, msg);
  t.ok(sig, 'produce sig');
  t.notok(subkey.verify(pubkey, sig, 'basics'), 'don\'t verify it');
});
