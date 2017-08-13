const db = new PouchDB('creds');
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
    console.log('origin doesn\t match');
    //throw new Error('origin doesn\'t match');
  }

  const result = {
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
*/
const verifyAuthData = function (authData) {

  const authDataHexArr = buf2hex(authData);
  const authDataLength = authDataHexArr.length;
  const rpIdHash = authDataHexArr.slice(0, 64);
  const flagsArr = authDataHexArr.slice(64, 66);
  const counter = authDataHexArr.slice(66, 74);
  const AAGUID = new Uint8Array();
  const credId = new Uint8Array();
  const publicKeyDict = new Map();

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

  // If Attestation Data is part of Authenticator Data: 
  if (flagsDict.AT) {

    AAGUID = authDataHexArr.slice(74, 106);

    const credIdByteLength = parseInt(authDataHexArr.slice(106, 110), 16);
    const endOfCredId = 110 + (credIdByteLength * 2);
    credId = authDataHexArr.slice(110, endOfCredId);

    const publicKeyCborHex = authDataHexArr.slice(endOfCredId, authDataHexArr.length);
    const publicKeyCborUint8 = hexstr2uint8(publicKeyCborHex);
    const publicKeyCborObj = CBOR.decode(publicKeyCborUint8.buffer);

    publicKeyDict.set(algName, publicKeyCborObj.algName);

    switch (publicKeyCborObj.algName) {
      case 'RS256' || 'RS384' || 'RS512' || 'PS256' || 'PS384' || 'PS512': 
        publicKeyDict.set('n', publicKeyCborObj.n);
        publicKeyDict.set('e', publicKeyCborObj.e);
        break;
      case 'ES256' || 'ES384' || 'ES512':
        publicKeyDict.set('x', publicKeyCborObj.x);
        publicKeyDict.set('y', publicKeyCborObj.y);
        break;
    }
  }

  const ClientSide_RpIdBuf = new TextEncoder().encode(localStorage.getItem('createCred' + '_ClientSide_RpId'));
  crypto.subtle.digest(SHA256, ClientSide_RpIdBuf).then(function (clientRpIdHash) {

    if (clientRpIdHash == authDataHexArr.rpIdHash) {
      console.log('Registration step 3: The RP ID hash in authData is matches the expectation')
    } else {
      throw new Error('RP ID hash doesn\'t match');
    }

  }).catch(function (err) {
    console.log(err);
  }); 


  // This approach won't work if there's extension in here. 
  // const attestationData = authData.slice(36, authDataLength - 1);
  // const credIdArr = attestationData.slice(18, endOfCredId);
  // const credIdStr = new TextDecoder().decode(credIdArr);
  // const AAGUID = attestationData.slice(0, 15);
  // const AAGUIDStr = ab2str(AAGUID);

  // const publicKeyCborDecoded = CBOR.decode(publicKeyCBOR);
  // console.log(publicKeyCborDecoded);

  return {
    rpIdHash: authData.slice(0, 31),
    flags: flagsDict,
    counter: authData.slice(33, 36),
    authDataByteLength: authData.byteLength,
    attestationData: attestationData,
    AAGUID: AAGUID,
    AAGUIDStr: AAGUIDStr,
    credIdArr: credIdArr,
    credIdStr: credIdStr,
    publicKeyCBOR: publicKeyCBOR,
    publicKeyDict: publicKeyDict,
  }

};


const serverRegisterCred = function (accountId, accountName, displayName, 
  id, rawId, clientDataJSON, attestationObj) {
  // TODO: I probably should move the dictionary code in here for the sake of more thorough testing. 
  
  // 1. Verify client data 
  const clientDataDict = verifyClientData('createCred', clientDataJSON);

  const attestationObjDict = CBOR.decode(attestationObj);

  const authDataDict = verifyAuthData(attestationObjDict.authData);

  db.put({
    _id: accountId,
    accountName: accountName,
    accountDisplayName: displayName,
    credId: id,
    credRawId: rawId,
    hashAlg: clientDataDict.hashAlg,
    attStmt: attestationObjDict.attStmt,
    fmt: attestationObjDict.fmt,
    publicKeyDict: authDataDict.publicKeyDict,
    AAGUID: authDataDict.AAGUID,
  }).then(function (response) {
    console.log(response);
    console.log('finish registration');

    return response.ok;
    // handle response
  }).catch(function (err) {
    console.log(err);
  });
}