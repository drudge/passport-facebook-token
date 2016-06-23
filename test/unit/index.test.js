import chai, { assert } from 'chai';
import sinon from 'sinon';
import FacebookTokenStrategy from '../../src/index';
import fakeProfile from '../fixtures/profile';

const STRATEGY_CONFIG = {
  clientID: '123',
  clientSecret: '123'
};

const BLANK_FUNCTION = () => {
};

describe('FacebookTokenStrategy:init', () => {
  it('Should properly export Strategy constructor', () => {
    assert.isFunction(FacebookTokenStrategy);
  });

  it('Should properly initialize', () => {
    let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    assert.equal(strategy.name, 'facebook-token');
    assert.equal(strategy._oauth2._useAuthorizationHeaderForGET, false);
  });

  it('Should properly throw exception when options is empty', () => {
    assert.throw(() => new FacebookTokenStrategy(), Error);
  });
  
  it('Should use the default fb graph version when no explicit version is specified', () => {
    let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    assert.equal(strategy._fbGraphVersion, 'v2.6');
    assert.equal(strategy._oauth2._accessTokenUrl,'https://graph.facebook.com/v2.6/oauth/access_token');
    assert.equal(strategy._oauth2._authorizeUrl,'https://www.facebook.com/v2.6/dialog/oauth');
    assert.equal(strategy._profileURL,'https://graph.facebook.com/v2.6/me');
  });
  
  it('Should use the explicit version, if specified', () => {
    let strategy = new FacebookTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      fbGraphVersion: 'v2.4'
    }, BLANK_FUNCTION);
    assert.equal(strategy._fbGraphVersion, 'v2.4');  
    assert.equal(strategy._oauth2._accessTokenUrl,'https://graph.facebook.com/v2.4/oauth/access_token');
    assert.equal(strategy._oauth2._authorizeUrl,'https://www.facebook.com/v2.4/dialog/oauth');
    assert.equal(strategy._profileURL,'https://graph.facebook.com/v2.4/me');	
  });
  
});

describe('FacebookTokenStrategy:authenticate', () => {
  describe('Authenticate without passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));
    });

    after(() => strategy._oauth2.get.restore());

    it('Should properly parse access_token from body', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access_token from query', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.query = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access token from OAuth2 bearer header', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.headers = {
            Authorization: 'Bearer access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access token from OAuth2 bearer header as lowercase', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.headers = {
            authorization: 'Bearer access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access token from access_token header', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.headers = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if access_token is not provided', done => {
      chai.passport.use(strategy).fail(error => {
        assert.typeOf(error, 'object');
        assert.typeOf(error.message, 'string');
        assert.equal(error.message, 'You should provide access_token');
        done();
      }).authenticate({});
    });
  });

  describe('Authenticate with passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new FacebookTokenStrategy({
        clientID: '123',
        clientSecret: '123',
        passReqToCallback: true
      }, (req, accessToken, refreshToken, profile, next) => {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));
    });

    after(() => strategy._oauth2.get.restore());

    it('Should properly call _verify with req', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });

  describe('Failed authentications', () => {
    it('Should properly return error on loadUserProfile', done => {
      let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy, '_loadUserProfile', (accessToken, next) => next(new Error('Some error occurred')));

      chai
        .passport
        .use(strategy)
        .error(error => {
          assert.instanceOf(error, Error);
          strategy._loadUserProfile.restore();
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', done => {
      let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(new Error('Some error occurred'));
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

      chai
        .passport
        .use(strategy)
        .error(error => {
          assert.instanceOf(error, Error);
          strategy._oauth2.get.restore();
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', done => {
      let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, null, 'INFO');
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

      chai
        .passport
        .use(strategy)
        .fail(error => {
          assert.equal(error, 'INFO');
          strategy._oauth2.get.restore();
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('FacebookTokenStrategy:userProfile', () => {
  it('Should properly fetch profile', done => {
    let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
      if (error) return done(error);

      assert.equal(profile.provider, 'facebook');
      assert.equal(profile.id, '794955667239296');
      assert.equal(profile._json.id, '794955667239296');
      assert.equal(profile.displayName, 'Eugene Obrezkov');
      assert.equal(profile.name.familyName, 'Obrezkov');
      assert.equal(profile.name.givenName, 'Eugene');
      assert.equal(profile.gender, 'male');
      assert.equal(profile.emails[0].value, 'ghaiklor@gmail.com');
      assert.equal(profile.photos[0].value, 'https://graph.facebook.com/v2.6/794955667239296/picture?type=large');
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      strategy._oauth2.get.restore();

      done();
    });
  });

  it('Should properly handle exception on fetching profile', done => {
    let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, 'not a JSON'));

    strategy.userProfile('accessToken', (error, profile) => {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly make request with enableProof', done => {
    let strategy = new FacebookTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      enableProof: true
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.equal(strategy._oauth2.get.getCall(0).args[0], 'https://graph.facebook.com/v2.6/me?appsecret_proof=8c340bd01643ab69939ca971314d7a3d64bfb18946cdde566f12fdbf6707d182&fields=id,name,last_name,first_name,middle_name,email');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly make request with profileFields', done => {
    let strategy = new FacebookTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      profileFields: ['name', 'custom']
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.equal(strategy._oauth2.get.getCall(0).args[0], 'https://graph.facebook.com/v2.6/me?appsecret_proof=8c340bd01643ab69939ca971314d7a3d64bfb18946cdde566f12fdbf6707d182&fields=last_name,first_name,middle_name,custom');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly throw error on _oauth2.get error', done => {
    let strategy = new FacebookTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next('Some error occurred'));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.instanceOf(error, Error);
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should use the proper profile image link with profileImage', done => {
    let strategy = new FacebookTokenStrategy({
      clientID: '123',
      clientSecret: '123',
      profileImage: {
        width: 1520,
        height: 1520
      }
    }, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
      if (error) return done(error);

      assert.equal(profile.photos[0].value, 'https://graph.facebook.com/v2.6/794955667239296/picture?width=1520&height=1520');

      strategy._oauth2.get.restore();
      done();
    });
  })
});

describe('FacebookTokenStrategy:convertProfileFields', () => {
  it('Should properly return string with pre-defined fields', () => {
    let string = FacebookTokenStrategy.convertProfileFields();
    assert.equal(string, '');
  });

  it('Should properly return string with custom fields', () => {
    let string = FacebookTokenStrategy.convertProfileFields(['username', 'name', 'emails', 'custom']);
    assert.equal(string, 'username,last_name,first_name,middle_name,email,custom');
  });
});
