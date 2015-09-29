var chai = require('chai');
var sinon = require('sinon');
var assert = chai.assert;
var FacebookTokenStrategy = require('../../index');
var fakeProfile = JSON.stringify(require('./../fixtures/profile.json'));

var STRATEGY_CONFIG = {
  clientID: '123',
  clientSecret: '123'
};

var BLANK_FUNCTION = function () {
};

describe('FacebookTokenStrategy:init', function () {
  it('Should properly export Strategy constructor', function () {
    assert.equal(typeof FacebookTokenStrategy, 'function');
    assert.equal(typeof FacebookTokenStrategy.Strategy, 'function');
    assert.equal(FacebookTokenStrategy, FacebookTokenStrategy.Strategy);
  });

  it('Should properly initialize', function () {
    var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    assert.equal(strategy.name, 'facebook-token');
    assert.equal(strategy._oauth2._useAuthorizationHeaderForGET, false);
  });

  it('Should properly throw exception when options is empty', function () {
    assert.throw(function () {
      new FacebookTokenStrategy();
    }, Error);
  });
});

describe('FacebookTokenStrategy:authenticate', function () {
  describe('Authenticate without passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {
          info: 'foo'
        });
      });

      sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
        next(null, fakeProfile, null);
      });
    });

    after(function () {
      strategy._oauth2.get.restore();
    });

    it('Should properly parse access_token from body', function (done) {
      chai
        .passport
        .use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {
            info: 'foo'
          });
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access_token from query', function (done) {
      chai
        .passport
        .use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {
            info: 'foo'
          });
          done();
        })
        .req(function (req) {
          req.query = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access_token from headers', function (done) {
      chai
        .passport
        .use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {
            info: 'foo'
          });
          done();
        })
        .req(function (req) {
          req.headers = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if access_token is not provided', function (done) {
      chai.passport.use(strategy).fail(function (error) {
        assert.typeOf(error, 'object');
        assert.typeOf(error.message, 'string');
        assert.equal(error.message, 'You should provide access_token');
        done();
      }).authenticate({});
    });
  });

  describe('Authenticate with passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new FacebookTokenStrategy({
        clientID: '123',
        clientSecret: '123',
        passReqToCallback: true
      }, function (req, accessToken, refreshToken, profile, next) {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {
          info: 'foo'
        });
      });

      sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
        next(null, fakeProfile, null);
      });
    });

    after(function () {
      strategy._oauth2.get.restore();
    });

    it('Should properly call _verify with req', function (done) {
      chai
        .passport
        .use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {
            info: 'foo'
          });
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });

  describe('Failed authentications', function () {
    it('Should properly return error on loadUserProfile', function (done) {
      var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {
          info: 'foo'
        });
      });

      sinon.stub(strategy, '_loadUserProfile', function (accessToken, next) {
        next(new Error('Some error occurred'));
      });

      chai
        .passport
        .use(strategy)
        .error(function (error) {
          assert.instanceOf(error, Error);
          strategy._loadUserProfile.restore();
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', function (done) {
      var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(new Error('Some error occurred'));
      });

      sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
        next(null, fakeProfile, null);
      });

      chai
        .passport
        .use(strategy)
        .error(function (error) {
          assert.instanceOf(error, Error);
          strategy._oauth2.get.restore();
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', function (done) {
      var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, null, 'INFO');
      });

      sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
        next(null, fakeProfile, null);
      });

      chai
        .passport
        .use(strategy)
        .fail(function (error) {
          assert.equal(error, 'INFO');
          strategy._oauth2.get.restore();
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('FacebookTokenStrategy:authorizationParams', function () {
  var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

  it('Should properly return empty object', function () {
    assert.deepEqual(strategy.authorizationParams(), {});
  });

  it('Should properly return object with display', function () {
    assert.deepEqual(strategy.authorizationParams({display: 'DISPLAY'}), {display: 'DISPLAY'});
  });
});

describe('FacebookTokenStrategy:userProfile', function () {
  it('Should properly fetch profile', function (done) {
    var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
      next(null, fakeProfile, null);
    });

    strategy.userProfile('accessToken', function (error, profile) {
      if (error) return done(error);

      assert.equal(profile.provider, 'facebook');
      assert.equal(profile.id, '794955667239296');
      assert.equal(profile._json.id, '794955667239296');
      assert.equal(profile.displayName, 'Eugene Obrezkov');
      assert.equal(profile.name.familyName, 'Obrezkov');
      assert.equal(profile.name.givenName, 'Eugene');
      assert.equal(profile.gender, 'male');
      assert.equal(profile.emails[0].value, 'ghaiklor@gmail.com');
      assert.equal(profile.photos[0].value, 'https://graph.facebook.com/794955667239296/picture?type=large');
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      strategy._oauth2.get.restore();

      done();
    });
  });

  it('Should properly handle exception on fetching profile', function (done) {
    var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
      next(null, 'not a JSON');
    });

    strategy.userProfile('accessToken', function (error, profile) {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly make request with enableProof', function (done) {
    var strategy = new FacebookTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      enableProof: true
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
      next(null, fakeProfile, null);
    });

    strategy.userProfile('accessToken', function (error, profile) {
      assert.equal(strategy._oauth2.get.getCall(0).args[0], 'https://graph.facebook.com/v2.2/me?appsecret_proof=8c340bd01643ab69939ca971314d7a3d64bfb18946cdde566f12fdbf6707d182');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly make request with profileFields', function (done) {
    var strategy = new FacebookTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      profileFields: ['username', 'name', 'custom']
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
      next(null, fakeProfile, null);
    });

    strategy.userProfile('accessToken', function (error, profile) {
      assert.equal(strategy._oauth2.get.getCall(0).args[0], 'https://graph.facebook.com/v2.2/me?fields=username,last_name,first_name,middle_name,custom');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly throw error on _oauth2.get error', function (done) {
    var strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', function (url, accessToken, next) {
      next('Some error occurred');
    });

    strategy.userProfile('accessToken', function (error, profile) {
      assert.instanceOf(error, Error);
      strategy._oauth2.get.restore();
      done();
    });
  });
});

describe('FacebookTokenStrategy:convertProfileFields', function () {
  var strategy = new FacebookTokenStrategy({
    clientID: '123',
    clientSecret: '123'
  }, function () {
  });

  it('Should properly return string with pre-defined fields', function () {
    var string = strategy._convertProfileFields();
    assert.equal(string, '');
  });

  it('Should properly return string with custom fields', function () {
    var string = strategy._convertProfileFields(['username', 'name', 'emails', 'custom']);
    assert.equal(string, 'username,last_name,first_name,middle_name,email,custom');
  });
});
