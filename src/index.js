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
    const options = _options || {};
    const verify = _verify;
    const _fbGraphVersion = options.fbGraphVersion || 'v2.6';

    options.authorizationURL = options.authorizationURL || `https://www.facebook.com/${_fbGraphVersion}/dialog/oauth`;
    options.tokenURL = options.tokenURL || `https://graph.facebook.com/${_fbGraphVersion}/oauth/access_token`;

    super(options, verify);

    this.name = 'facebook-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileURL = options.profileURL || `https://graph.facebook.com/${_fbGraphVersion}/me`;
    this._profileFields = options.profileFields || ['id', 'displayName', 'name', 'emails'];
    this._profileImage = options.profileImage || {};
    this._clientSecret = options.clientSecret;
    this._clientID = options.clientID;
    this._enableProof = typeof options.enableProof === 'boolean' ? options.enableProof : true;
    this._passReqToCallback = options.passReqToCallback;
    this._oauth2.useAuthorizationHeaderforGET(false);
    this._fbGraphVersion = _fbGraphVersion;
    this.tokenURL = options.tokenURL;
    this._getLongLivedToken = options.getLongLivedToken || false;
    this._storeLongLiveToken = options.storeLongLiveToken || false;
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   * @param {Object} req
   * @param {Object} options
   */
  authenticate(req, options) {
    const accessToken = this.lookup(req, this._accessTokenField);
    const refreshToken = this.lookup(req, this._refreshTokenField);
    const self=this;
    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };
      const passCallback=(req,accessToken,refreshToken,profile) => {
        if (self._storeLongLiveToken){
          accessToken=req.body.longLivedToken
        }

        if (self._passReqToCallback) {
          self._verify(req, accessToken, refreshToken, profile, verified);
        } else {
          self._verify(accessToken, refreshToken, profile, verified);
        }
      };
      if(self._getLongLivedToken) {
        self._getLLT(accessToken, function (err, longLivedToken, expires) {
          if(err){
            self.error(err);
            return;
          }

          req.body.longLivedToken = longLivedToken;
          if(expires !== null){
            req.body.longLivedTokenExpires = expires;
          }
          passCallback(req, accessToken, refreshToken, profile);
        });
      } else {
        passCallback(req, accessToken, refreshToken, profile);
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
    let profileURL = uri.parse(this._profileURL);

    // For further details, refer to https://developers.facebook.com/docs/reference/api/securing-graph-api/
    if (this._enableProof) {
      const proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
      profileURL.search = `${profileURL.search ? profileURL.search + '&' : ''}appsecret_proof=${encodeURIComponent(proof) }`;
    }

    // Parse profile fields
    if (this._profileFields) {
      const fields = FacebookTokenStrategy.convertProfileFields(this._profileFields);
      profileURL.search = `${profileURL.search ? profileURL.search + '&' : ''}fields=${fields}`;
    }

    profileURL = uri.format(profileURL);

    this._oauth2.get(profileURL, accessToken, (error, body, res) => {
      if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

      try {
        const json = JSON.parse(body);

        // Get image URL based on profileImage options
        let imageUrl = uri.parse(`https://graph.facebook.com/${this._fbGraphVersion}/${json.id}/picture`);
        if (this._profileImage.width) imageUrl.search = `width=${this._profileImage.width}`;
        if (this._profileImage.height) imageUrl.search = `${imageUrl.search ? imageUrl.search + '&' : ''}height=${this._profileImage.height}`;
        imageUrl.search = `${imageUrl.search ? imageUrl.search : 'type=large'}`;
        imageUrl = uri.format(imageUrl);

        const profile = {
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
            value: imageUrl
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
   * Parses an OAuth2 RFC6750 bearer authorization token, this method additionally is RFC 2616 compliant and respects
   * case insensitive headers.
   *
   * @param {Object} req http request object
   * @returns {String} value for field within body, query, or headers
   */
  parseOAuth2Token(req) {
    const OAuth2AuthorizationField = 'Authorization';
    const headerValue = (req.headers && (req.headers[OAuth2AuthorizationField] || req.headers[OAuth2AuthorizationField.toLowerCase()]));

    return (
      headerValue && (() => {
        const bearerRE = /Bearer\ (.*)/;
        let match = bearerRE.exec(headerValue);
        return (match && match[1]);
      })()
    );
  }

  /**
   * Performs a lookup of the param field within the request, this method handles searhing the body, query, and header.
   * Additionally this method is RFC 2616 compliant and allows for case insensitive headers. This method additionally will
   * delegate outwards to the OAuth2Token parser to validate whether a OAuth2 bearer token has been provided.
   *
   * @param {Object} req http request object
   * @param {String} field
   * @returns {String} value for field within body, query, or headers
   */
  lookup(req, field) {
    return (
      req.body && req.body[field] ||
      req.query && req.query[field] ||
      req.headers && (req.headers[field] || req.headers[field.toLowerCase()]) ||
      this.parseOAuth2Token(req)
    );
  }

  /**
   * Converts array of profile fields to string
   * @param {Array} _profileFields Profile fields i.e. ['id', 'email']
   * @returns {String}
   */
  static convertProfileFields(_profileFields) {
    let profileFields = _profileFields || [];
    let map = {
      'id': 'id',
      'displayName': 'name',
      'name': ['last_name', 'first_name', 'middle_name'],
      'gender': 'gender',
      'profileUrl': 'link',
      'emails': 'email',
      'photos': 'picture'
    };

    return profileFields.reduce((acc, field) => acc.concat(map[field] || field), []).join(',');
  }
  /**
   * Attempts to get a Long-Lived Token from Facebook.
   * Requires a valid clientID (AppID), clientSecret (AppSecret) and accessToken
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api private
   */
  _getLLT(accessToken,done){
    let url = this.tokenURL + "?" +
      "grant_type=fb_exchange_token" + "&" +
      "client_id=" + this._clientID + "&" +
      "client_secret=" + this._clientSecret + "&" +
      "fb_exchange_token=" + accessToken;
    url = uri.parse(url);

    if (this._enableProof) {
      // Secure API call by adding proof of the app secret.  This is required when
      // the "Require AppSecret Proof for Server API calls" setting has been
      // enabled.  The proof is a SHA256 hash of the access token, using the app
      // secret as the key.
      //
      // For further details, refer to:
      // https://developers.facebook.com/docs/reference/api/securing-graph-api/
      const proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
      url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
    }
    url = uri.format(url);
    this._oauth2.getProtectedResource(url, accessToken, function (err, body, res) {
      if (err) {
        return done(new InternalOAuthError('failed to get long-lived token', err)); }
      try {
        body=JSON.parse(body);
        if(typeof body.access_token === "undefined"){
          return done(new InternalOAuthError('facebook was unable to provide a long-lived token'));
        }
        if(typeof body.expires_in === "undefined"){
          body.expires_in = null;
        }
        return done(null,body.access_token,body.expires_in)
      } catch(e) {
        done(e);
      }
    });
  }

}
