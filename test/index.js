var crypto = require('crypto');

var Promise = require('bluebird');
var assert = require('chai').assert;
var _ = require('lodash');

var Passworks = require('../index');

var simpleConfig = { keyLength: 64, strategy: 'pbkdf2', iterations: 1000 };
var md5Config = _.defaults({ algorithm: 'SHA1', strategy: 'simple' }, simpleConfig);

function simpleStrategy(password) {
	return crypto.createHash(this.algorithm).update(password).digest('hex');
}

describe('Passworks', function () {
	afterEach(function () {
		Passworks.init();
	});

	it('should instantiate with config', function (done) {
		Passworks.init({ keyLength: 64 });

		var pw = new Passworks();

		assert.equal(pw.keyLength, 64);

		done();
	});

	it('should throw if instantiated without config', function (done) {
		try {
			var pw = new Passworks();

			done(new Error('No TypeError thrown'));
		} catch (err) {
			assert.match(err, /Passworks.init/);
			assert.instanceOf(err, TypeError);

			done();
		}
	});

	describe('#genSalt()', function () {
		it('should generate a salt on instantiation', function () {
			Passworks.init({ keyLength: 100 });

			var pw = new Passworks();

			assert.property(pw, 'salt');
		});

		it('should generate a salt with the configured length', function () {
			Passworks.init({ keyLength: 100 });

			var pw = new Passworks();

			assert.lengthOf(pw.salt, 200);
		});

		it('should generate a salt with the configured length as a string', function () {
			Passworks.init({ keyLength: '101' });

			var pw = new Passworks();

			assert.lengthOf(pw.salt, 202);
		});
	});

	describe('#digest()', function () {
		it('should resolve the instance', function () {
			Passworks.init(simpleConfig);

			var pw = new Passworks();

			return pw.digest('digestsecret')
				.then(function (that) {
					assert.instanceOf(that, Passworks);
				});
		});

		it('should resolve the hash', function () {
			Passworks.init(simpleConfig);

			var pw = new Passworks();

			return Promise.all([
				crypto.pbkdf2Async('resolvesecret', pw.salt, simpleConfig.iterations, simpleConfig.keyLength).call('toString', 'hex'),
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

		it('should throw on invalid strategy', function () {
			Passworks.init(simpleConfig);

			var pw = new Passworks({ strategy: 'invalid' });

			return pw.digest('test')
				.then(function () {
					throw new Error('Should throw');
				})
				.catch(Passworks.StrategyError);
		});
	});

	describe('#matches()', function () {
		it('should match a password', function () {
			Passworks.init(simpleConfig);

			var pw = new Passworks();

			return pw.digest('matchSecret').call('matches', 'matchSecret');
		});

		it('should reject an invalid password', function () {
			Passworks.init(simpleConfig);

			var pw = new Passworks();

			return pw.digest('matchSecret').call('matches', 'bad')
				.then(function () {
					throw new Error('Shouldn\'t match');
				})
				.catch(Passworks.PasswordError);
		});
	});

	describe('#addStrategy', function () {
		it('should add a strategy', function () {
			Passworks.addStrategy('test', function () {});

			assert.deepProperty(Passworks, 'prototype.strategies.test');
		});

		it('should throw when attempting to replace an existing strategy', function () {
			try {
				Passworks.addStrategy('test');
			} catch (err) {
				assert.instanceOf(err, Passworks.StrategyError);
				assert.match(err, /already exists/);

				return;
			}

			assert.fail(null, null, 'Expected RangeError');
		});

		it('should throw when fn is not a function', function () {
			try {
				Passworks.addStrategy('testNoFn');
			} catch (err) {
				assert.instanceOf(err, Passworks.StrategyError);
				assert.match(err, /Expected second argument "fn" to be a function/);

				return;
			}

			assert.fail(null, null, 'Expected RangeError');
		});
	});

	describe('#fromString()', function () {
		it('should return an instance', function () {
			Passworks.init(simpleConfig);

			var pw = Passworks.fromString(':::::');

			assert.instanceOf(pw, Passworks);
		});

		it('should set the expected properties', function () {
			Passworks.init(simpleConfig);

			var pw = Passworks.fromString('strat:alg:10:20:sa:ha');

			assert.propertyVal(pw, 'strategy', 'strat');
			assert.propertyVal(pw, 'algorithm', 'alg');
			assert.propertyVal(pw, 'iterations', 10);
			assert.propertyVal(pw, 'keyLength', 20);
			assert.propertyVal(pw, 'salt', 'sa');
			assert.propertyVal(pw, 'hash', 'ha');
		});
	});

	describe('#toString()', function () {
		it('should convert to string', function () {
			Passworks.init(simpleConfig);

			var pwString = 'strat:alg:10:20:sa:ha';
			var pw = Passworks.fromString(pwString);

			assert.equal(pw.toString(), pwString);
		});
	});
});
