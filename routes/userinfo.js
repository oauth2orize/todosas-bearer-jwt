var createError = require('http-errors');
var express = require('express');
var passport = require('passport');
var HTTPBearerStrategy = require('passport-http-bearer');
var jws = require('jws');
var db = require('../db');


passport.use(new HTTPBearerStrategy(function verify(token, cb) {
  var now = Math.floor(Date.now() / 1000);
  var jwt = jws.decode(token, { json: true });
  if (jwt.payload.iss !== 'https://server.example.com') { return cb(null, false); }
  if (jwt.payload.aud !== 'https://api.example.com') { return cb(null, false); }
  if (jwt.payload.exp <= now) { return cb(null, false); }
  
  var ok = jws.verify(token, 'HS256', 'has a van');
  if (!ok) { return cb(null, false); }
  
  var user = {
    id: parseInt(jwt.payload.sub)
  };
  var authInfo = {
    scope: jwt.payload.scope ? jwt.payload.scope.split(' ') : []
  };
  return cb(null, user, authInfo);
}));


var router = express.Router();

router.get('/userinfo', passport.authenticate('bearer', { session: false, failWithError: true }), function(req, res, next) {
  db.get('SELECT * FROM users WHERE id = ?', [ req.user.id ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return next(createError(403)); }
    var info = {
      sub: row.id.toString()
    };
    if (req.authInfo.scope.indexOf('profile') != -1) {
      if (row.name) { info.name = row.name; }
      if (row.username) { info.preferred_username = row.username; }
    }
    if (req.authInfo.scope.indexOf('email') != -1) {
      if (row.email) { info.email = row.email; }
      if (row.email_verified) { info.email_verified = row.email_verified; }
    }
    if (req.authInfo.scope.indexOf('phone') != -1) {
      if (row.phone_number) { info.phone_number = row.phone_number; }
      if (row.phone_number_verified) { info.phone_number_verified = row.phone_number_verified; }
    }
    res.json(info);
  });
}, function(err, req, res, next) {
  res.status(err.status || 500);
  return res.end();
});

module.exports = router;
