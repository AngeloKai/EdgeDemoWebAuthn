var createCredButton = document.getElementById('test1');
var createResult = document.getElementById('createResult');
var createDatabase = document.getElementById('createDatabase');


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
    challenge: receivedChallengeStr,
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
      console.log('Registration step 3: The RP ID hash in authData is matches the expectation');

      return result;

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
  const credIdStr = arrayBufferToBase64(authDataDict.credId);

  /* Show output */
  const output = "clientDataJSON:" + "\n" 
  + "challenge: " + clientDataDict.challenge + "\n"
  + "origin" +  clientDataDict.origin + "\n"
  + "hashAlg" + clientDataDict.hashAlg;

  createResult.innerHTML = output;

  const publicKeyCred = {
    credId: authDataDict.credId,
    publicKeyDict: authDataDict.publicKeyDict,
  };

  /* The database is indexed by CredId
     This is a sample schema:
      {
        "credId": 111111111111111,
        "accountId": 111111111111, 
        "accountName": JaneDoe@contoso.com, 
        "displayName": Jane Doe,
        "publicDict": {

        },
        "AAGUID":
        "counter": 
        rpIdHash: 
        flagsDict: {

        }
      }
  */ 
  // Reconcile document update failure by checking accountId
  
  credDB.get(credIdStr).then(function (doc) {
    return credDB.put({
      _id: credIdStr,
      _rev: doc._rev,
      accountId: accountId.toString(),
      accountName: accountName,
      displayName: displayName,
      publicKeyDict: authDataDict.publicKeyDict,
      AAGUID: authDataDict.AAGUID,
      counter: authDataDict.counter,
      rpIdHash: authDataDict.rpIdHash,
      flagsDict: authDataDict.flagsDict,
    });
  }).then(function (response) {
    // handle response 
    if (response.ok) {
      console.log('Successfully update the document after create');
    }
  }).catch(function (err) {
    if (err.name == 'not_found') {
      return {
        documentId: credId.toString(),
      }
    } else {
      console.log('Unable to update document after create' + err);
    }
  }).then(function (accountDoc) {
    return credDB.put({
      _id: credId.toString(),
      accountId: accountId.toString(),
      accountName: accountName,
      displayName: displayName,
      publicKeyDict: authDataDict.publicKeyDict,
      AAGUID: authDataDict.AAGUID,
      counter: authDataDict.counter,
      rpIdHash: authDataDict.rpIdHash,
      flagsDict: authDataDict.flagsDict,
    })
  }).then(function (response){
    if (response.ok) {
      console.log('An unique account was created and an unique cred is added');

      return credDB.allDocs({include_docs: true});

    } else {
      console.log('Unable to add document');

      const error = "response failed";
      return error;
    }
  }).then(function (result) {
    if (result != "response failed") {
      return createDatabase.innerHTML = JSON.stringify(result, undefined, 2);      
    } else {
      return result;
    }
  }).catch(function (err) {
      console.log('store database failed: ');
      console.log(err);
      createDatabase.innerHTML = error;      
  });

};

const serverVerifyCred = function (id, rawId, clientDataJSON, authenticatorData, sig) {
  // 1. Verify client data
  const clientDataDict = verifyClientData('verifyCred', clientDataJSON);

  // 2. Verify RP ID Hash
  const authDataDict = verifyAuthData(authenticatorData);

  var cryptoKey;
  var aDataHash;
  var alg;

  // switch (authDataDict.publicKeyDict.alg) {
  //   case 'RS256' || 'RS384' || 'RS512' || 'PS256' || "PS384" || 'PS512':
  //     // RSASSA-PKCS1-v1_5 is the same as RS256.
  //     alg = 'RSASSA-PKCS1-v1_5';
  //     break;
  //   case 'ES256' || 'ES384' || 'ES512':
  //     alg = 'ECDSA';
  //     break;
  // }

    //   "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
    // {   //this is an example jwk key, other key types are Uint8Array objects
    //     kty: "EC",
    //     crv: "P-256",
    //     x: "zCQ5BPHPCLZYgdpo1n-x_90P2Ij52d53YVwTh3ZdiMo",
    //     y: "pDfQTUx0-OiZc5ZuKMcA7v2Q7ZPKsQwzB58bft0JTko",
    //     ext: true,
    // },
    // {   //these are the algorithm options
    //     name: "ECDSA",
    //     namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
    // },
    // false, //whether the key is extractable (i.e. can be used in exportKey)
    // ["verify"] //"verify" for public key import, "sign" for private key imports

  // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding
  //    is inappropriate for your use case), look up the corresponding credential public key.
  credDB.createIndex({  
    index: {fields: ['accountId']}  /* Create index to search the db by attribute */
  }).then(function () {
    return credDB.find({
      selector: {
        publicKeyCreds: {
          $elemMatch: {
            _id: authDataDict.credId,
        }}
      }
    })
  }).then(function(result) {
    if (result.length != 1) {
      throw new Error('more than 1 cred is found');
    } else {
      var publicKeyDict = result[0].publicKeyCreds[0].publicKeyDict;
      return crypto.subtle.importKey(
        'jwk',
        {
          kty: 'RSA',
          crv: 'P-256',
          e: publicKeyDict.e,
          n: publicKeyDict.n,
          use: 'verify'
        },
        {
          name: 'RSASSA-PKCS1-v1_5',
          namedCurve: 'P-256'
        },
        false,
        ['verify']
      )
    }
  }).then(function (publicCryptoKey) {
    cryptoKey = publicCryptoKey;
    return crypto.subtle.digest(clientDataDict.hashAlg, clientDataJSON);
  }).then(function (clientDataHash) {
    aDataHash = concatArrBuffer(authenticatorData, clientDataHash);
    
    // 5. Using the credential public key looked up in step 1, verify that sig is a valid signature over
    //    the binary concatenation of aData and hash.
    // RSASSA-PKCS1-v1_5 is the same as RS256.
    return crypto.subtle.verify(webCryptoAlg, cryptoKey, sig, aDataHash);
  }).then(function (isValid) {

    if (isValid) {
      console.log('sig is valid!');
    } else {
      console.log('something went wrong');
    }
    
  }).catch(function (err) {
    console.log(err);
  });
    
  
};