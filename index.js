var pkginfo = require('pkginfo'),
    Strategy = require('./lib/Strategy');

pkginfo(module, 'version');

module.exports = Strategy;
module.exports.Strategy = Strategy;
