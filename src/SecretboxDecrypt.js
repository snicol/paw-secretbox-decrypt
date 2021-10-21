const nacl = require('tweetnacl');
const naclutil = require('tweetnacl-util');

class SecretboxDecrypt {
	evaluate() {
		if([this.message, this.key, this.nonce].some(v => v === null))
			return '';

		const res = nacl.secretbox.open(
			naclutil.decodeBase64(this.message),
			naclutil.decodeBase64(this.nonce),
			naclutil.decodeBase64(this.key)
		);

		if (res === null)
			return 'authenticating message failed';

		return naclutil.encodeUTF8(res);
	}
}

SecretboxDecrypt.identifier = 'com.snicol.SecretboxDecrypt';
SecretboxDecrypt.title = 'Secretbox Decrypt';
SecretboxDecrypt.help = 'https://github.com/snicol/paw-secretbox-decrypt';

SecretboxDecrypt.inputs = [
	InputField('message', 'Message', 'SecureValue', {
		persisted: true,
	}),
	InputField('key', 'Key', 'SecureValue', {
		persisted: true,
	}),
	InputField('nonce', 'Nonce', 'SecureValue', {
		persisted: true,
	}),
];

registerDynamicValueClass(SecretboxDecrypt);
