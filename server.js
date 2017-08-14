const accountDB = new PouchDB('accounts');
// The remoteCouch should be updated if a remote server is used for this app. 
const remoteCouch = false;



/*
  verifyClientData takes in the clientDataJSON object (an ArrayBuffer): 
    https://www.w3.org/TR/2017/WD-webauthn-20170505/#dom-authenticatorresponse-clientdatajson

  It verifies whether the challenge and origin in clientDataJSON is as expected. 

  It returns the following field:
   - challenge as a base64 decoded string 
   - origin as a string
   - hashAlg as a string
   - tokenBindingId as a base64 decoded string (if present)
*/
const verifyClientData = function (stage, buf) {
  // ArrayBuffer is converted to a UTF-8 string and then a JSON object. with
  const clientDataJSONStr = new TextDecoder().decode(buf);
  const clientDataJsonObj = JSON.parse(clientDataJSONStr);
  const receivedChallengeStr = atob(clientDataJsonObj.challenge);
  const receivedOrigin = clientDataJsonObj.origin;

  // 2. Verify the challenge matches the challenges used. 
  const sentChallengeStr = localStorage.getItem(stage + '_ClientSide_ChallengeStr');
  if (receivedChallengeStr == sentChallengeStr) {
    console.log('Registration Step 1: Challenge in clientDataJSON matches the Server')
  } else {
    throw new Error('challeng doesn\'t match');
  }

  // 3. Verify the origin matches the origin of the script. 
  const sentOrigin = localStorage.getItem(stage + '_ClientSide_Origin');
  if (receivedOrigin == sentOrigin) {
    console.log('Registration Step 2: Origin in clientDataJSON matches the Server');
  } else {
    console.log('origin does not match');
    //throw new Error('origin doesn\'t match');
  }

  var result = {
    challeng: receivedChallengeStr,
    origin: receivedOrigin,
    hashAlg: clientDataJsonObj.hashAlg,
  };

  if (clientDataJsonObj.tokenBinding) {
    result.set('tbId', atob(clientDataJsonObj.tokenBindingId));
  }

  return result;
};

/* More information about authenticator data can be found here: 
  https://w3c.github.io/webauthn/#sec-attestation-data 
  
  verifyAuthData returns: 
  - AAGUID (as string representation of its hex characters)
  - counter (same above)
  - credId (same above)
  - rpIdHash, a hash of a buffer containing the UTF-8 encoded RP ID.  
  - flagsDict, a dictionary of set flags, including AT, TUP, and ED.
  - publicKeyDict, a dictionary of public key info. 
    In the case of "RS256" / "RS384" / "RS512" / "PS256" / "PS384" / "PS512":
      The dict will have alg, e, n.
    In the case of "ES256" / "ES384" / "ES512":
      The dict will have alg, x, y. 
*/
const verifyAuthData = function (authData) {

  const authDataHexArr = buf2hex(authData);
  const authDataLength = authDataHexArr.length;
  const rpIdHash = authDataHexArr.slice(0, 64);
  var result = {rpIdHash};
  const flagsArr = authDataHexArr.slice(64, 66);
  const counter = authDataHexArr.slice(66, 74);
  result.counter = counter;

  const flagsDict = {};

  if (hexToBinary(flagsArr).valid) {
    const flagsBinStr = hexToBinary(flagsArr).result;

    // Check if ED bit is set
    if (flagsBinStr[0] == 1) {
      // ED flag represents whether any extension is added.
      console.log('Authentication Info: ED flag is set.');
      flagsDict.ED = true; 
    }

    if (flagsBinStr[1] == 1) {
      // AT flag represents whether attestation data is added to authenticator data. 
      console.log('Authentication Info: AT flag is set.');
      flagsDict.AT = true;
    }

    if (flagsBinStr[7] == 1) {
      console.log('Authentication Info: TUP flag is set.');
      flagsDict.TUP = true; 
    }
  }

  result.flagsDict = flagsDict;

  // If Attestation Data is part of Authenticator Data: 
  if (flagsDict.AT) {

    result.AAGUID = authDataHexArr.slice(74, 106);

    const credIdByteLength = parseInt(authDataHexArr.slice(106, 110), 16);
    const endOfCredId = 110 + (credIdByteLength * 2);
    result.credId = authDataHexArr.slice(110, endOfCredId);

    const publicKeyCborHex = authDataHexArr.slice(endOfCredId, authDataHexArr.length);
    const publicKeyCborUint8 = hexstr2uint8(publicKeyCborHex);
    result.publicKeyDict = CBOR.decode(publicKeyCborUint8.buffer);
  }

  const ClientSide_RpIdBuf = new TextEncoder().encode(localStorage.getItem('createCred' + '_ClientSide_RpId'));
  crypto.subtle.digest(SHA256, ClientSide_RpIdBuf).then(function (clientRpIdHash) {

    if (buf2hex(clientRpIdHash) == rpIdHash) {
      console.log('Registration step 3: The RP ID hash in authData is matches the expectation')
    } else {
      throw new Error('RP ID hash doesn\'t match');
    }

  }).catch(function (err) {
    console.log(err);
  }); 

  return result;

};


const serverRegisterCred = function (accountId, accountName, displayName, 
  id, rawId, clientDataJSON, attestationObj) {
  // TODO: I probably should move the dictionary code in here for the sake of more thorough testing. 
  
  // 1. Verify client data 
  const clientDataDict = verifyClientData('createCred', clientDataJSON);
  // hashAlg needs to be stored. 

  const attestationObjDict = CBOR.decode(attestationObj);

  const authDataDict = verifyAuthData(attestationObjDict.authData);

  const credId = authDataDict.credId;

  accountDB.put({
    _id: accountId.toString(),
    accountName: accountName,
    displayName, displayName,
    publicKeyCreds: [{
      credId: authDataDict.credId,
      publicKeyDict: authDataDict.publicKeyDict,
      AAGUID: authDataDict.AAGUID,
      counter: authDataDict.counter,
      rpIdHash: authDataDict.rpIdHash,
      flagsDict: authDataDict.flagsDict,
    }]
  }).then(function (response){
    if (response.ok) {
      console.log('store data for' + response.ok);
    } else {
      console.log('got data')
    }
  }).catch(function (err) {
      console.log('store database failed: ');
      console.log(err);
  });

};

var publicKeyDict;

const serverVerifyCred = function (id, rawId, clientDataJSON, authenticatorData, sig) {
  // 1. Verify client data
  const clientDataDict = verifyClientData('verifyCred', clientDataJSON);

  // 2. Verify RP ID Hash
  const authDataDict = verifyAuthData(authenticatorData);

  var cryptoKey;
  var aDataHash;

  // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding
  //    is inappropriate for your use case), look up the corresponding credential public key.
  accountDB.createIndex({  
    index: {fields: ['publicKeyCreds']}  /* Create index to search the db by attribute */
  }).then(function () {
    return accountDB.find({
      selector: {
        publicKeyCreds: {
          $elemMatch: {
            credId: authDataDict.credId,
        }}
      }
    })
  }).then(function(result) {
    if (result.length != 1) {
      throw new Error('more than 1 cred is found');
    } else {
      var publicKeyDict = result[0].publicKeyCreds[0].publicKeyDict;
      return crypto.subtle.importKey(
        // RSASSA-PKCS1-v1_5 is the same as RS256.
      )
    }
  }).then(function (publicCryptoKey) {
    cryptoKey = publicCryptoKey;
    return crypto.subtle.digest(clientDataDict.hashAlg, clientDataJSON);
  }).then(function (clientDataHash) {
    aDataHash = new ArrayBuffer(authenticatorData.length + clientDataHash.length);
    aDataHash = ;
    
    // 5. Using the credential public key looked up in step 1, verify that sig is a valid signature over
    //    the binary concatenation of aData and hash.
    // RSASSA-PKCS1-v1_5 is the same as RS256.
    return crypto.subtle.verify(publicKeyDict.alg, publicKeyDict.key, sig, aDataHash);
  }).then(function (isValid) {
    gotoHome();

  }).catch(function (err) {
    console.log(err);
  });
    
  

};