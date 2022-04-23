var express = require('express');
var passport = require('passport');
var HTTPBearerStrategy = require('passport-http-bearer');
var db = require('../db');


passport.use(new HTTPBearerStrategy(function verify(token, cb) {
  db.get('SELECT * FROM access_tokens WHERE token = ?', [
    token
  ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false); }
    var user = {
      id: row.user_id
    };
    // TODO: Pass scope as info
    return cb(null, user);
  });
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
