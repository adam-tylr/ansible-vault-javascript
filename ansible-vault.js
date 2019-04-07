/*
 *  Compatible with vault payload format 1.1
 *	https://docs.ansible.com/ansible/latest/user_guide/vault.html#vault-payload-format-1-1
 */
const VAULT_HEADER = '$ANSIBLE_VAULT;1.1;AES256';
const VAULT_LINE_LENGTH = 80;
const AES_BLOCK_SIZE = 16;
const SALT_LENGTH = 32;
const BITS_PER_BYTE = 8;

// Key Derivation
const PBKDF2 = 'PBKDF2';
const HASH = {name: "SHA-256"};
const ITERATIONS = 10000;
const KEY_LENGTH = 80;

const textEncoder = new TextEncoder("utf-8");

async function decrypt(vault, password) {
	checkProtocol();
	const vaultComponents = validateAndParseVault(vault);

	return deriveKey(hexStringToUint8Array(vaultComponents.salt), password)
		.then((key) => {
			return verify(key.hmacKey, vaultComponents.hmac, vaultComponents.data)
				.then((isValid) => {
					if (isValid) {
						return key;
					}
					throw 'Invalid signature';
				});
		})
		.then((key) => {
			return decryptVault(key.cipherKey, key.iv, vaultComponents.data);
		});
}

async function encrypt(input, password) {
	checkProtocol();
	const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
	const data = encodeInput(input);
	let cipherText;
	let key;

	return deriveKey(salt, password)
		.then((k) => {
			key = k;
			return encryptVault(key.cipherKey, key.iv, data);
		})
		.then((encrypted) => {
			cipherText = encrypted;
			return sign(key.hmacKey, cipherText);
		})
		.then((signature) => {
			return encodeVault(salt, signature, cipherText);
		})
}

function encodeVault(salt, hmac, data) {
	const vault = [uint8ArrayToHexString(salt), hmac, data].join('\n');
	const hexVault = hexlify(vault);
	const chunks = chunkSubstr(hexVault, VAULT_LINE_LENGTH);
	return [VAULT_HEADER, ...chunks].join('\n');
}

function validateAndParseVault(vault) {
	const lines = vault.split('\n');
	if (lines.length < 2) {
		throw 'Vault should have at least 2 lines';
	}

	if (lines[0].trim() !== VAULT_HEADER) {
		throw `Vault should begin with ${VAULT_HEADER}`
	}

	lines.splice(0, 1);
	const hexEncodedVaultText = lines.join('');
	const decoded = unhexlify(hexEncodedVaultText);
	const vaultComponents = decoded.split('\n');

	if (vaultComponents.length !== 3) {
		throw 'Vault text is invalid';
	}
	return {
		salt: vaultComponents[0],
		hmac: vaultComponents[1],
		data: vaultComponents[2],
	};
}

function deriveKey(salt, password) {
  	const passwordBuffer = textEncoder.encode(password);
  	return window.crypto.subtle.importKey("raw", passwordBuffer, PBKDF2, false, ["deriveBits"])
  		.then((key) => {
  			const params = {
  				name: PBKDF2, 
  				hash: HASH, 
  				salt: salt,
  				iterations: ITERATIONS
  			};
  			return window.crypto.subtle.deriveBits(params, key, KEY_LENGTH * BITS_PER_BYTE);
  		})
  		.then((derivedBuffer) => {
  			return parseKey(derivedBuffer);
  		});
}

function parseKey(keyBuffer) {
	const hexKey = Array.prototype.map.call(
  			new Uint8Array(keyBuffer), x => ('00' + x.toString(16)).slice(-2)).join('');
	return {
		// first 32 bytes
		cipherKey: hexKey.substr(0, 64),
		// second 32 bytes
		hmacKey: hexKey.substr(64, 64),
		// last 16 bytes
		iv: hexKey.substr(128, 32),
	};
}

function verify(hmacKey, signature, data) {
	return window.crypto.subtle.importKey(
	    "raw", hexStringToUint8Array(hmacKey),
	    {
	        name: "HMAC",
	        hash: {name: "SHA-256"},
	    },
	    false,
	    ["verify"]
	).then((key) => {
		return window.crypto.subtle.verify(
		    {
		        name: "HMAC",
		    },
		    key, 
		    hexStringToUint8Array(signature),
		    hexStringToUint8Array(data)
		);
	});
}

function sign(hmacKey, cipherText) {
	return window.crypto.subtle.importKey(
	    "raw", hexStringToUint8Array(hmacKey),
	    {
	        name: "HMAC",
	        hash: {name: "SHA-256"},
	    },
	    false,
	    ["sign"]
	).then((key) => {
		return window.crypto.subtle.sign(
		    {
		        name: "HMAC",
		    },
		    key, 
		    hexStringToUint8Array(cipherText),
		);
	}).then((signatureBuffer) => {
		return uint8ArrayToHexString(new Uint8Array(signatureBuffer));
	});
}

function decryptVault(cipherKey, iv, data) {
	return window.crypto.subtle.importKey(
		"raw",
		hexStringToUint8Array(cipherKey),
	    {name: "AES-CTR",},
		false,
		["decrypt"]
	).then((key) => {
		return window.crypto.subtle.decrypt(
			{
				name: "aes-ctr",
				counter: hexStringToUint8Array(iv),
				length: 128,
			},
			key,
			hexStringToUint8Array(data)
		);
	}).then((decrypted) => {
		return decodeDecryptedBytes(decrypted);
	});
}

function decodeDecryptedBytes(decryptedBytes) {
	const bytes = new Uint8Array(decryptedBytes);
	const length = bytes.length;
	const padLength = bytes[length-1];
	const unpadded = bytes.slice(0, length - padLength);
	return String.fromCharCode.apply(null, unpadded);
}

function encryptVault(cipherKey, iv, data) {
	return window.crypto.subtle.importKey(
		"raw",
		hexStringToUint8Array(cipherKey),
	    {name: "AES-CTR",},
		false,
		["encrypt"]
	).then((key) => {
		return window.crypto.subtle.encrypt(
			{
				name: "aes-ctr",
				counter: hexStringToUint8Array(iv),
				length:128
			},
			key,
			data
		);
	}).then((encrypted) => {
		return uint8ArrayToHexString(new Uint8Array(encrypted));
	});
}

function encodeInput(input) {
	const hexInput = hexlify(input);
	const bytes = hexStringToUint8Array(hexInput);
	const padLength = AES_BLOCK_SIZE - hexInput.length/2 % AES_BLOCK_SIZE;
	const paddedInput = new Uint8Array(bytes.length + padLength);

	for (let i = 0; i < bytes.length; i += 1) {
		paddedInput[i] = bytes[i];
	}
	paddedInput.fill(padLength, bytes.length, paddedInput.length);
	return paddedInput;
}

function unhexlify(str) {
    var result = '';
    for (var i=0, l=str.length; i<l; i+=2) {
      result += String.fromCharCode(parseInt(str.substr(i, 2), 16));
    }
    return result;
};

function hexlify(str) {
	var result = '';
    var padding = '00';
    for (var i=0, l=str.length; i<l; i++) {
      var digit = str.charCodeAt(i).toString(16);
      var padded = (padding+digit).slice(-2);
      result += padded;
    }
    return result;
}

function hexStringToUint8Array(hexString) {
    if (hexString.length % 2 != 0)
        throw "Invalid hexString";
    var arrayBuffer = new Uint8Array(hexString.length / 2);

    for (var i = 0; i < hexString.length; i += 2) {
        var byteValue = parseInt(hexString.substr(i, 2), 16);
        if (byteValue == NaN)
            throw "Invalid hexString";
        arrayBuffer[i/2] = byteValue;
    }

    return arrayBuffer;
}

function uint8ArrayToHexString(uint8Array) {
	return Array.prototype.map.call(uint8Array, x => ('00' + x.toString(16)).slice(-2)).join('');
}

function checkProtocol() {
	if ('https:' !== document.location.protocol) {
		throw 'ansibile-vault requires an https connection';
	}
}

function chunkSubstr(str, size) {
  const numChunks = Math.ceil(str.length / size)
  const chunks = new Array(numChunks)

  for (let i = 0, o = 0; i < numChunks; ++i, o += size) {
    chunks[i] = str.substr(o, size)
  }

  return chunks
}

export default {
	encrypt,
	decrypt,
};
