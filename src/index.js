import uri from 'url';
import crypto from 'crypto';
import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

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
export default class FacebookTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://www.facebook.com/v2.4/dialog/oauth';
    options.tokenURL = options.tokenURL || 'https://graph.facebook.com/oauth/access_token';

    super(options, verify);

    this.name = 'facebook-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileURL = options.profileURL || 'https://graph.facebook.com/v2.4/me';
    this._profileFields = options.profileFields || ['id', 'name', 'emails'];
    this._clientSecret = options.clientSecret;
    this._enableProof = typeof options.enableProof === 'boolean' ? options.enableProof : true;
    this._passReqToCallback = options.passReqToCallback;

    this._oauth2.useAuthorizationHeaderforGET(false);
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   * @param {Object} req
   * @param {Object} options
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
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
  userProfile(accessToken, done) {
    let url = uri.parse(this._profileURL);

    if (this._enableProof) {
      // For further details, refer to https://developers.facebook.com/docs/reference/api/securing-graph-api/
      let proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
      url.search = `${url.search ? url.search + '&' : ''}appsecret_proof=${encodeURIComponent(proof)}`;
    }

    if (this._profileFields) {
      let fields = this._convertProfileFields(this._profileFields);
      url.search = `${url.search ? url.search + '&' : ''}fields=${fields}`;
    }

    url = uri.format(url);

    this._oauth2.get(url, accessToken, (error, body, res) => {
      if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

      try {
        let json = JSON.parse(body);
        let profile = {
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
            value: `https://graph.facebook.com/${json.id}/picture?type=large`
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
  _convertProfileFields(_profileFields) {
    let profileFields = _profileFields || [];
    let fields = [];
    let map = {
      'id': 'id',
      'displayName': 'name',
      'name': ['last_name', 'first_name', 'middle_name'],
      'gender': 'gender',
      'profileUrl': 'link',
      'emails': 'email',
      'photos': 'picture'
    };

    profileFields.forEach(field => {
      if (typeof map[field] === 'undefined') return fields.push(field);

      if (Array.isArray(map[field])) {
        Array.prototype.push.apply(fields, map[field]);
      } else {
        fields.push(map[field]);
      }
    });

    return fields.join(',');
  }
}
