/**
 * Responsible for the bulk of the work of authenticating against the Faithlife
 * OAuth provider.
 */
var util = require('util');
var OAuthStrategy = require('passport-oauth1').Strategy;

/**
 * Creates a new instance of FaithlifeStrategy with the provided `options`.
 * - `consumerKey` - The OAuth consumer key from developer.faithlife.com.
 * - `consumerSecret` - The OAuth consumer secret from developer.faithlife.com.
 * - `callbackURL` - URL to which Faithlife will redirect the user after
 *   obtaining authorization.
 * - `signatureMethod` - The signature method to use for OAuth transactions.
 *   Defaults to `HMAC-SHA1`.
 *
 * Applications must supply a callback which accepts a `token` and `secret`
 * (the access credentials), a Faithlife-specific `profile`, and a Node-style
 * callback. The callback should be called with either a valid User or `false`
 * (if the credentials are invalid), or an appropriate error.
 *
 * @param {Object} options
 * @param {Function} verify
 */
function FaithlifeStrategy(options, verify) {
  if (!(this instanceof FaithlifeStrategy)) {
    return new FaithlifeStrategy(options);
  }

  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://auth.faithlife.com/v1/temporarytoken';
  options.accessTokenURL = options.accessTokenURL || 'https://auth.faithlife.com/v1/accesstoken';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://auth.faithlife.com/v1/authorize';
  options.signatureMethod = options.signatureMethod || 'HMAC-SHA1';

  OAuthStrategy.call(this, options, verify);

  this.name = 'faithlife';
}
util.inherits(FaithlifeStrategy, OAuthStrategy);

/*!
 * Export `FaithlifeStrategy`.
 */
module.exports = FaithlifeStrategy;
