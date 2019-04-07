# ansible-vault-javascript

A simple javascript ansible vault client to encrypt and decrypt vaults

## Usage
```
import ansibleVault from './ansible-vault.js';

let vault;

// encrypt
const plainText = 
`---
dbPassword: toni123`;
  
ansibleVault.encrypt(plainText, 'secretVaultPassword')
  .then((encrypted) => {
    vault = encrypted;
    console.log(encrypted);
  })
  .catch((error) => {
    console.error(error);
  });
  
// output:
// $ANSIBLE_VAULT;1.1;AES256
// 63653266316464336533316333346264663164646462336366326435346134636664656536653233
// 3637393330623262383266316366656436323639663963320a353334343936373533326436393734
// 37353839363964666439313434373765376439373161363434303766313132663838613264313031
// 3631356238316239310a373365613238646462646563663965393636333233316634656538376531
// 32313764653566633932346330393666653765303431313830633833643036303231

// decrypt

ansibleVault.decrypt(vault, 'secretVaultPassword')
  .then((decrypted) => {
    console.log(decrypted);
  })
  .catch((error) => {
    console.error(error);
  })
  
// output:
// ---
// dbPassword: toni123
```
