'use strict';

var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _url = require('url');

var _url2 = _interopRequireDefault(_url);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _passportOauth = require('passport-oauth');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

/**
 * `FacebookTokenStrategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * @param {Object} options
 * @param {Function} verify
 * @example
 * passport.use(new FacebookTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), (accessToken, refreshToken, profile, done) => {
 *   User.findOrCreate({facebookId: profile.id}, done);
 * });
 */

var FacebookTokenStrategy = (function (_OAuth2Strategy) {
  _inherits(FacebookTokenStrategy, _OAuth2Strategy);

  function FacebookTokenStrategy(_options, _verify) {
    _classCallCheck(this, FacebookTokenStrategy);

    var options = _options || {};
    var verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://www.facebook.com/v2.4/dialog/oauth';
    options.tokenURL = options.tokenURL || 'https://graph.facebook.com/oauth/access_token';

    var _this = _possibleConstructorReturn(this, Object.getPrototypeOf(FacebookTokenStrategy).call(this, options, verify));

    _this.name = 'facebook-token';
    _this._authorizationField = options.authorizationField || 'Authorization';
    _this._accessTokenField = options.accessTokenField || 'access_token';
    _this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    _this._profileURL = options.profileURL || 'https://graph.facebook.com/v2.4/me';
    _this._profileFields = options.profileFields || ['id', 'displayName', 'name', 'emails'];
    _this._clientSecret = options.clientSecret;
    _this._enableProof = typeof options.enableProof === 'boolean' ? options.enableProof : true;
    _this._passReqToCallback = options.passReqToCallback;
    _this._oauth2.useAuthorizationHeaderforGET(false);
    return _this;
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   * @param {Object} req
   * @param {Object} options
   */

  _createClass(FacebookTokenStrategy, [{
    key: 'authenticate',
    value: function authenticate(req, options) {
      var _this2 = this;

      var accessToken = req.body && req.body[this._accessTokenField] || req.query && req.query[this._accessTokenField] || FacebookTokenStrategy.parseAccessTokenHeader(req.headers, this._accessTokenField, this._authorizationField);
      var refreshToken = req.body && req.body[this._refreshTokenField] || req.query && req.query[this._refreshTokenField] || req.headers && req.headers[this._refreshTokenField];

      if (!accessToken) return this.fail({ message: 'You should provide ' + this._accessTokenField });

      this._loadUserProfile(accessToken, function (error, profile) {
        if (error) return _this2.error(error);

        var verified = function verified(error, user, info) {
          if (error) return _this2.error(error);
          if (!user) return _this2.fail(info);

          return _this2.success(user, info);
        };

        if (_this2._passReqToCallback) {
          _this2._verify(req, accessToken, refreshToken, profile, verified);
        } else {
          _this2._verify(accessToken, refreshToken, profile, verified);
        }
      });
    }

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
     */

  }, {
    key: 'userProfile',
    value: function userProfile(accessToken, done) {
      var url = _url2.default.parse(this._profileURL);

      if (this._enableProof) {
        // For further details, refer to https://developers.facebook.com/docs/reference/api/securing-graph-api/
        var proof = _crypto2.default.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
        url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
      }

      if (this._profileFields) {
        var fields = FacebookTokenStrategy.convertProfileFields(this._profileFields);
        url.search = (url.search ? url.search + '&' : '') + 'fields=' + fields;
      }

      url = _url2.default.format(url);

      this._oauth2.get(url, accessToken, function (error, body, res) {
        if (error) return done(new _passportOauth.InternalOAuthError('Failed to fetch user profile', error));

        try {
          var json = JSON.parse(body);
          var profile = {
            provider: 'facebook',
            id: json.id,
            displayName: json.name || '',
            name: {
              familyName: json.last_name || '',
              givenName: json.first_name || '',
              middleName: json.middle_name || ''
            },
            gender: json.gender || '',
            emails: [{
              value: json.email || ''
            }],
            photos: [{
              value: 'https://graph.facebook.com/' + json.id + '/picture?type=large'
            }],
            _raw: body,
            _json: json
          };

          done(null, profile);
        } catch (e) {
          done(e);
        }
      });
    }

    /**
     * Converts array of profile fields to string
     * @param {Array} _profileFields Profile fields i.e. ['id', 'email']
     * @returns {String}
     */

  }], [{
    key: 'convertProfileFields',
    value: function convertProfileFields(_profileFields) {
      var profileFields = _profileFields || [];
      var map = {
        'id': 'id',
        'displayName': 'name',
        'name': ['last_name', 'first_name', 'middle_name'],
        'gender': 'gender',
        'profileUrl': 'link',
        'emails': 'email',
        'photos': 'picture'
      };

      return profileFields.reduce(function (acc, field) {
        return acc.concat(map[field] || field);
      }, []).join(',');
    }

    /**
    * Parses an access token from the headers object using a custom header or via OAuth2 RFC6750 bearer authorization
    * @param {Object} headers header object from a request
    * @param {String} accessTokenField custom http field with access token directly set
    * @param {String} authorizationField secondary http field that is RFC6750 compliant
    * @returns {String} access token
    */

  }, {
    key: 'parseAccessTokenHeader',
    value: function parseAccessTokenHeader(headers, accessTokenField, authorizationField) {
      // headers should be case insensitive, some libraries (like unirest) will lowercase all headers automatically
      // lowercasing custom accessTokenField since users can override it       
      if (headers && (headers[accessTokenField] || headers[accessTokenField.toLowerCase()])) {
        return headers[accessTokenField];
      } else if (headers && (headers[authorizationField] || headers[authorizationField.toLowerCase()])) {
        var bearerRE = /Bearer\ (.*)/;
        var header = headers[authorizationField] || headers[authorizationField.toLowerCase()];
        var match = bearerRE.exec(header);
        return match[1];
      }
    }
  }]);

  return FacebookTokenStrategy;
})(_passportOauth.OAuth2Strategy);

exports.default = FacebookTokenStrategy;
module.exports = exports['default'];