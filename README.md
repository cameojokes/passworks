## passworks - simple javascript password library

passworks provides a simple and versatile interface for managing password hashes.

- Extensible strategy support.
- Password validation.
- Error handling.
- Generate strings and objects with strategy meta data.
- Loading from generated strings and objects.

The only included strategy is PBKDF2. You'll need to call `Passworks.init()` first to set that strategy, and other options.

#### API Usage

##### `Passworks.init(options)`

Set options for new instances. Must be called prior to any `new` instantiation.
```
Passworks.init({
	strategy: 'pbkdf2',
	algorithm: 'SHA512',
	iterations: 128000,
	keyLength: 32
});
```

##### `Passworks.digest(secret[, returnHash])`

Perform key derivation and digest of the string argument `secret`.

Sets the derived hash digest string to the instance. Returns a promise resolved and bound to `this`.

When the returnHash argument is `true`, resolves as the hash string without setting the `hash` property of the instance.

```
var pw = new Passworks();

// Derive and digest. Setting `this.hash` to the derived key.
ps.digest('somepassword') // Promise - passworks instance

// Derive, digest, and return a promise resolved with the hash.
ps.digest('anotherpassword')
	.tap(console.log); // 687e6e5bde7369d263d360e42aff51d1
```

##### `Passworks.matches(secret)`

Check if an instance hash matches the hash of the provided `secret`;

Returns a promise resolved and bound to `this` if the hash matches. Rejects with a Passworks.PasswordError otherwise.

```
var pw = new Passworks('mysecret');

pw.matches('mysecret')
	.then(function() {
		// Password is valid
	});

// Failure
pw.matches('badsecret')
	.catch(Passworks.PasswordError, function() {
		// Password is invalid
	});
```

##### `Passworks.addStrategy(strategy, fn)`

Add a password strategy function. PBKDF2 is currently the only provided strategy. The function should return the hash string, or a Promise if async.

```
Passworks.addStrategy('simple', function(secret) {
	return crypto.createHash(this.algorithm).update(secret).digest('hex');
});

Passworks.init({
	strategy: 'simple',
	keyLength: 16,
	algorithm: 'md5' }
);

var pw = new Passworks();

pw.digest('weaksecret')
	.call('toString')
	.tap(console.log); // simple:md5::16:b82d330d81b01168f963daeb94e3bfa9:b7dec8884bcff8bc682ded0292f3efe2
```

##### `Passworks.toString()`

Return a string containing the hash and other meta data in the format: `strategy:algorithm:iterations:keyLength:salt:hash`

```
pw.toString(); // pbkdf2:SHA512:1000:16:036b12783633b4684682d640ec2d8db9:101d7f1fe4fbe10305834c6cd03b2aa0
```

##### `Passworks.fromString()`

Create a passworks instance from a string.

```
Passworks.fromString('pbkdf2:SHA512:1000:16:036b12783633b4684682d640ec2d8db9:101d7f1fe4fbe10305834c6cd03b2aa0');
```

##### `Passworks.toObject([keyLength])`

Returns a simple object representation of the password hash and meta data:

```
{
	strategy: this.strategy,
	algorithm: this.algorithm,
	iterations: this.iterations,
	keyLength: this.keyLength,
	salt: this.salt,
	hash: this.hash
};
```

##### `Passworks.fromObject([keyLength])`

Creates and returns a passworks instance from an object.

```
var passwordObject = {
	strategy: 'pbkdf2',
	algorithm: 'SHA512'
	iterations: 128000,
	keyLength: 64,
	salt: '036b12783633b4684682d640ec2d8db9',
	hash: '101d7f1fe4fbe10305834c6cd03b2aa0'
}

var pw = Passworks.fromObject(passwordObject);
```

##### `Passworks.genSalt([keyLength])`

Called by default on instantiation. Returns a hex string using  `options.keyLength` byte length when an instance, keyLength argument statically.

Uses `crypto.randomBytes()`.

```
var salt = Passworks.genSalt(16); // e1292b9291ef5c2edfa1735f3e348b8c
```
