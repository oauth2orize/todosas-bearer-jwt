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
  // TODO: Pass scope as info
  return cb(null, user);
}));


var router = express.Router();

router.get('/userinfo', passport.authenticate('bearer', { session: false }), function(req, res, next) {
  db.get('SELECT * FROM users WHERE id = ?', [ req.user.id ], function(err, row) {
    if (err) { return next(err); }
    // TODO: Handle undefined row.
    var info = {
      sub: row.id.toString()
    };
    // TODO: check scope
    if (row.name) { info.name = row.name; }
    if (row.username) { info.preferred_username = row.username; }
    res.json(info);
  });
});

module.exports = router;
