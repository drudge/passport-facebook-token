/**
 * Module dependencies.
 */
var util = require('util')
  , uri = require('url')
  , crypto = require('crypto')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `FacebookTokenStrategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 * 
 * Options:
 *   - `clientID`      your Facebook application's App ID
 *   - `clientSecret`  your Facebook application's App Secret
 *
 * Examples:
 *
 *     passport.use(new FacebookTokenStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function FacebookTokenStrategy(options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://www.facebook.com/dialog/oauth';
  options.tokenURL = options.tokenURL || 'https://graph.facebook.com/oauth/access_token';
  options.scopeSeparator = options.scopeSeparator || ',';

  this._passReqToCallback = options.passReqToCallback;
  
  OAuth2Strategy.call(this, options, verify);
  this._profileURL = options.profileURL || 'https://graph.facebook.com/me';
  this.name = 'facebook-token';
  this._clientSecret = options.clientSecret;
  this._enableProof = options.enableProof;
  this._profileFields = options.profileFields || null;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(FacebookTokenStrategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
FacebookTokenStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }
  
  // req.body may not be present, but token may be present in querystring
  var accessToken,refreshToken;
  if(req.body){
	  accessToken = req.body.access_token;
	  refreshToken = req.body.refresh_token;
  }
  
  accessToken = accessToken || req.query.access_token;
  refreshToken = refreshToken || req.query.refresh_token;
  
  if (!accessToken) {
	  return this.fail();
  }
  
  self._loadUserProfile(accessToken, function(err, profile) {
    if (err) { return self.fail(err); };
    
    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }
      self.success(user, info);
    }
    
    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
}

/**
 * Return extra Facebook-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
FacebookTokenStrategy.prototype.authorizationParams = function (options) {
  var params = {},
      display = options.display;

  if (display) {
    params['display'] = display;
  }

  return params;
};

/**
 * Retrieve user profile from Facebook.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `facebook`
 *   - `id`               the user's Facebook ID
 *   - `username`         the user's Facebook username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Facebook
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
FacebookTokenStrategy.prototype.userProfile = function(accessToken, done) {
  var url = uri.parse(this._profileURL);
  if (this._enableProof) {
    // Secure API call by adding proof of the app secret.  This is required when
    // the "Require AppSecret Proof for Server API calls" setting has been
    // enabled.  The proof is a SHA256 hash of the access token, using the app
    // secret as the key.
    //
    // For further details, refer to:
    // https://developers.facebook.com/docs/reference/api/securing-graph-api/    
    var proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
    url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
  }
  if (this._profileFields) {
    var fields = this._convertProfileFields(this._profileFields);
    if (fields !== '') { url.search = (url.search ? url.search + '&' : '') + 'fields=' + fields; }
  }
  url = uri.format(url);

  this._oauth2.getProtectedResource(url, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'facebook' };
      profile.id = json.id;
      profile.username = json.username;
      profile.displayName = json.name;
      profile.name = { familyName: json.last_name,
                       givenName: json.first_name,
                       middleName: json.middle_name };
      profile.gender = json.gender;
      profile.profileUrl = json.link;
      profile.emails = [{ value: json.email }];

      if (json.picture) {
        if (typeof json.picture == 'object' && json.picture.data) {
          // October 2012 Breaking Changes
          profile.photos = [{ value: json.picture.data.url }];
        } else {
          profile.photos = [{ value: json.picture }];
        }
      }
      
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
FacebookTokenStrategy.prototype._loadUserProfile = function(accessToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
}

FacebookTokenStrategy.prototype._convertProfileFields = function(profileFields) {
  var map = {
    'id':          'id',
    'username':    'username',
    'displayName': 'name',
    'name':       ['last_name', 'first_name', 'middle_name'],
    'gender':      'gender',
    'profileUrl':  'link',
    'emails':      'email',
    'photos':      'picture'
  };
  
  var fields = [];
  
  profileFields.forEach(function(f) {
    if (typeof map[f] === 'undefined') { return; }

    if (Array.isArray(map[f])) {
      Array.prototype.push.apply(fields, map[f]);
    } else {
      fields.push(map[f]);
    }
  });

  return fields.join(',');
};


/**
 * Expose `FacebookTokenStrategy`.
 */ 
module.exports = FacebookTokenStrategy;
