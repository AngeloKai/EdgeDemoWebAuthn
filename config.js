/* Common schemes */ 
const SHA256 = 'SHA-256';
const accountId = 1234;

new PouchDB('accounts').destory().then(function (response) {
    const credDB = new PouchDB('accounts');
    return credDB;
}).catch(function (err) {
    console.log (err);
});
// The remoteCouch should be updated if a remote server is used for this app. 
const remoteCouch = false;