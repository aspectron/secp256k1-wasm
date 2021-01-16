// ensure only a single instance of secp256k1 exists
// in the node environment as multiple instances may
// be problematic when loading wasm asynchronously
if(!global.__secp256k1__)
	global.__secp256k1__ = require('./http/secp256k1');
module.exports = global.__secp256k1__;