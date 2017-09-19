/* Common schemes */ 
const SHA256 = 'SHA-256';
const accountId = 1234;

const credDB = new PouchDB('accounts');
// The remoteCouch should be updated if a remote server is used for this app. 
const remoteCouch = false;