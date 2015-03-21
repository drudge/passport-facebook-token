var pkginfo = require('pkginfo');
var Strategy = require('./lib/strategy');

pkginfo(module, 'version');

module.exports = Strategy;
module.exports.Strategy = Strategy;
