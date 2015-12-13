var crypto = require('crypto');

var Promise = require('bluebird');
var assert = require('chai').assert;
var _ = require('lodash');

var Passworks = require('../index');

var baseConfig = { keyLen: 64, strategy: 'pbkdf2', iterations: 128000 };
var md5Config = _.defaults({ algorithm: 'SHA1', strategy: 'simple' }, baseConfig);

function simpleStrategy(password) {
	return crypto.createHash(this.algorithm).update(password).digest('hex');
}

describe('Passworks', function () {
	afterEach(function () {
		Passworks.init();
	});

	it('should instantiate with config', function (done) {
		Passworks.init({ keyLen: 64 });

		var pw = new Passworks();

		assert.equal(pw.keyLen, 64);

		done();
	});

	it('should throw if instantiated without config', function (done) {
		try {
			var pw = new Passworks();

			done(new Error('No TypeError thrown'));
		} catch (err) {
			assert.match(err, /Passworks.init/);
			assert.isTrue(err instanceof TypeError);

			done();
		}
	});

	describe('#genSalt()', function () {
		it('should generate a salt on instantiation', function () {
			Passworks.init({ keyLen: 100 });

			var pw = new Passworks();

			assert.property(pw, 'salt');
		});

		it('should generate a salt with the configured length', function () {
			Passworks.init({ keyLen: 100 });

			var pw = new Passworks();

			assert.lengthOf(pw.salt, 200);
		});

		it('should generate a salt with the configured length as a string', function () {
			Passworks.init({ keyLen: '101' });

			var pw = new Passworks();

			assert.lengthOf(pw.salt, 202);
		});
	});

	describe('#digest()', function () {
		it('should resolve the instance', function () {
			Passworks.init(baseConfig);

			var pw = new Passworks();

			return pw.digest('digestsecret')
				.then(function (that) {
					assert.instanceOf(that, Passworks);
				});
		});

		it('should resolve the hash', function () {
			Passworks.init(baseConfig);

			var pw = new Passworks();

			return Promise.all([
				crypto.pbkdf2Async('resolvesecret', pw.salt, baseConfig.iterations, baseConfig.keyLen).call('toString', 'hex'),
				pw.digest('resolvesecret').get('hash')
			])
				.spread(function (expectedHash, actualHash) {
					assert.equal(expectedHash, actualHash);
				});
		});

		it('should digest an external strategy', function () {
			Passworks.init(md5Config);

			Passworks.addStrategy('simple', simpleStrategy);

			var pw = new Passworks();

			return pw.digest('externalsecret', true)
				.then(function (hash) {
					assert.equal(hash, crypto.createHash('SHA1').update('externalsecret').digest('hex'));
				});
		});
	});

	describe('#matches()', function () {
		it('should match a password', function () {
			Passworks.init(baseConfig);

			var pw = new Passworks();

			return pw.digest('matchSecret').call('matches', 'matchSecret');
		});
	});
});