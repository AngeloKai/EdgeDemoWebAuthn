if (!PublicKeyCredential) {
  alert('navigator.credentials.create namespace does not exist');
}

/* Common schemes */ 
const SHA256 = 'SHA-256';
const accountId = 1234;

/* Buttons */
var button1 = document.getElementById('test1')
button1.style.color = 'blue';

var button2 = document.getElementById('verify');
button2.style.color = 'orange';

const buttonToBlack = function(button) {
  button.style.color = 'black';
};

const buttonToGreen = function(button) {
  button.style.color = 'green';
};

// Convert ArrayBuffer to UTF-8 string. 
// This should really be taken out once TextEncoder is shipped. 
const ab2str = function (buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
};

// Convert from hex to binary
// E.g. from 41 to 01000001
function hexToBinary(s) {
    var i, k, part, ret = '';
    // lookup table for easier conversion. '0' characters are padded for '1' to '7'
    var lookupTable = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100',
        '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001',
        'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101',
        'e': '1110', 'f': '1111',
        'A': '1010', 'B': '1011', 'C': '1100', 'D': '1101',
        'E': '1110', 'F': '1111'
    };
    for (i = 0; i < s.length; i += 1) {
        if (lookupTable.hasOwnProperty(s[i])) {
            ret += lookupTable[s[i]];
        } else {
            return { valid: false };
        }
    }
    return { valid: true, result: ret };
};

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

const decodeClientData = function (buf) {
        // ArrayBuffer is converted to a UTF-8 string and then a JSON object. with
  const clientDataJsonObj = JSON.parse(ab2str(buf));
  console.log(clientDataJsonObj);
  const challenge = clientDataJsonObj.challenge;
  const origin = clientDataJsonObj.origin;
  const hashAlg = clientDataJsonObj.hashAlg;
  const tbId = clientDataJsonObj.tokenBindingId; 

  console.log(origin);
};

const decodeAttestationObj = function (buf) {
  const decoded = CBOR.decoded(buf);
  const attStmt = decoded.attStmt;
  const authData = decoded.authData;
  const fmt = decoded.fmt;
  // decodeAuthData(authData);
  console.log(decoded);
};

const hexstr2uint8 = function (hexStr) {
  var uint8 = new Uint8Array(hexStr.match(/[\da-f]{2}/gi).map(function (h) {
    return parseInt(h, 16)
  }));

  return uint8;
};

/* More information about authenticator data can be found here: 
  https://w3c.github.io/webauthn/#sec-attestation-data 
*/
const decodeAuthData = function (authData) {

  const authDataHexArr = buf2hex(authData);

  const authDataLength = authDataHexArr.length;

  var rpIdHash = authDataHexArr.slice(0, 64);
  const ClientSide_RpIdBuf = new TextEncoder().encode(localStorage.getItem('ClientSide_RpId'));
  crypto.subtle.digest(SHA256, ClientSide_RpIdBuf).then(function (clientRpIdHash) {

    console.log('computed RP ID has: ');
    console.log(buf2hex(clientRpIdHash));

    console.log('RP ID hash from Client Data: ');
    console.log(buf2hex(rpIdHash));

      // 8. Verify that the RP ID hash in authData(retrieved in step 3) matches the hash 
      //    retrieved in step 7.
    if (clientRpIdHash != authDataHexArr.rpIdHash) {
      throw new Error('RP ID hash doesn\'t match');
    };
  }).catch(function (err) {

  }); 

  // The flags added up perfectly. It should say the AT and TUP flags are both 1 and the rest are 0. 
  const flagsArr = authDataHexArr.slice(64, 66);
  const flags = {};

  if (hexToBinary(flagsArr).valid) {
    const flagsBinStr = hexToBinary(flagsArr).result;
    console.log('flag str is: ');
    console.log(flagsBinStr);

    // Check if ED bit is set
    if (flagsBinStr[0] == 1) {
      // ED flag represents whether any extension is added.
      console.log('ED flag is set.');
      flags.ED = true; 
    }

    if (flagsBinStr[1] == 1) {
      // AT flag represents whether attestation data is added to authenticator data. 
      console.log('AT flag is set.');
      flags.AT = true;
    }

    if (flagsBinStr[7] == 1) {
      console.log('TUP flag is set.');
      flags.TUP = true; 
    }
  }

  const counter = authDataHexArr.slice(66, 74);
  
  // const AAGUID;
  // const credIdByteLength;
  // const credId;
  // const publicKeyCBOR;

  if (flags.AT) {

    const AAGUID = authDataHexArr.slice(74, 106);
    const credIdByteLength = parseInt(authDataHexArr.slice(106, 110), 16);
    const endOfCredId = 110 + (credIdByteLength * 2);
    const credId = authDataHexArr.slice(110, endOfCredId);
    const publicKeyCborHex = authDataHexArr.slice(endOfCredId, authDataHexArr.length);

    const publicKeyCborUint8 = hexstr2uint8(publicKeyCborHex);
    const publicKeyCborObj = CBOR.decode(publicKeyCborUint8.buffer);

  }

  // This approach won't work if there's extension in here. 
  const attestationData = authData.slice(36, authDataLength - 1);

  const credIdArr = attestationData.slice(18, endOfCredId);
  const credIdStr = new TextDecoder().decode(credIdArr);
  const AAGUID = attestationData.slice(0, 15);
  const AAGUIDStr = ab2str(AAGUID);

  const publicKeyCborDecoded = CBOR.decode(publicKeyCBOR);
  console.log(publicKeyCborDecoded);

  var authData = {
    // I counted the length of everything and compared them to the event viewer. They almost add up. 
    rpIdHash: authData.slice(0, 31),
    flags: flags,
    counter: authData.slice(33, 36),
    authDataByteLength: authData.byteLength,
    attestationData: attestationData,
    AAGUID: AAGUID,
    AAGUIDStr: AAGUIDStr,
    credIdArr: credIdArr,
    credIdStr: credIdStr,
    publicKeyCBOR: publicKeyCBOR
  }

  return authData;

};

const decodeAttestData = function (attestationData) {
  const AAGUID = attestationData.slice(0, 15);
  const credIdByteLength = attestationData.slice(16, 17);
  const endOfCredId = 17 + credIdByteLength;
  const credId = attestationData.slice(18, endOfCredId);
  const attestDataLength = attestationData.length;
  const publicKeyCBOR = attestationData.slice(endOfCredId, attestDataLength - 1);

  decodePublicKey(publicKeyCBOR);
};

const decodePublicKey = function (publicKeyCBOR) {
  const publicKeyMap = CBOR.decode(publicKeyCBOR);
  const publicKeyAlg = publicKeyMap.alg;
  //TODO more about public key stuff. 
}

const validateCreation = function (id, rawId, clientDataJSON, attestationObj) {
  // TODO: I should have used atob here but unfortunately there's a bug.
  localStorage.setItem(accountId + '_Id', id);
  localStorage.setItem(accountId + '_RawId', ab2str(rawId));

  // 1. Decode clientDataJSON. 
  const clientDataJsonObj = JSON.parse(ab2str(clientDataJSON));

  // 2. Verify the challenge matches the challenges used. 
  const serverChallengeStr = atob(clientDataJsonObj.challenge);
  const clientChallengeStr = localStorage.getItem('ClientSide_ChallengeStr');
  if (serverChallengeStr != clientChallengeStr) {
    throw new Error('challeng doesn\'t match');
  }

  // 3. Verify the origin matches the origin of the script. 
  const serverOrigin = clientDataJsonObj.origin;
  const clientOrigin = localStorage.getItem('ClientSide_Origin');
  if (serverOrigin == clientOrigin) {
    throw new Error('origin doesn\'t match');
  }

  // 4. Document the hash algorithm. 
  const hashAlg = clientDataJsonObj.hashAlg;

  // 5. TODO: Verify the Token Binding ID used during the TLS connection.
  if (clientDataJsonObj.tokenBindingId) {
    const tbId = clientDataJsonObj.tokenBindingId;
  } 
  
  // 5. Compute a hash of the clientDataJSON using the hash algorithm identified in step 4 and document 
  //    it as clientDataHash
  // crypto.subtle.digest({name: hashAlg}, clientDataJSON).then( function(clientDataHash) {
  //   // TODO
  // }).catch(function (err) {
  //   // The issue could be with the hash algorithm.
  //   console.log('The hash alg is: ' + hashAlg);
  //   console.log(err);
  // });

  // 6.  Perform CBOR decoding on the attestationObject to obtain the attestation statement format fmt, the 
  //     authenticator data authData, and the attestation statement attStmt. 
  const decoded = CBOR.decode(attestationObj);
  const attStmt = decoded.attStmt;
  const authData = decoded.authData;
  const fmt = decoded.fmt;

  console.log(buf2hex(authData));

  const authDataInfo = decodeAuthData(authData);

  // 7. Compute a SHA-256 hash of the RP ID.
  const ClientSide_RpId = localStorage.getItem('ClientSide_RpId');
  crypto.subtle.digest({name: SHA256}, ClientSide_RpId).then(function (clientRpIdHash) {

      // 8. Verify that the RP ID hash in authData(retrieved in step 3) matches the hash 
      //    retrieved in step 7.
    if (clientRpIdHash != authDataInfo.rpIdHash) {
      throw new Error('RP ID hash doesn\'t match');
    };

    // 9. Validate attestation statement attSmt if present. 
    if (attStmt) {
      // TODO. 
    };

    // Memorizing the AAGUID is not necessary but a good idea to do.
    localStorage.setItem(accountId + '_AAGUID', authDataInfo.AAGUIDStr);
    localStorage.setItem(accountId + 'CredIdStr', authDataInfo.credIdStr);


  }).catch(function (err) {

  }); 

  // 10. Associate the credential ID and publicKey found in authData with account ID used in create. 

	decodeClientData(clientData);
  decodeAttestationObj(attestationObj);
;}

const logClientScriptInfo = function(rpId, challenge) {
  const origin = window.location;
  localStorage.setItem('ClientSide_Origin', origin);

  localStorage.setItem('ClientSide_RpId', rpId);

  const challengeStr = new TextDecoder().decode(challenge);
  localStorage.setItem('ClientSide_ChallengeStr', challengeStr);

};

const createCred = function() {
  const newChallenge = new TextEncoder().encode('Windows Hello');
  //const newChallenge = new Uint8Array(stringToBytes('Windows Hello'));

	var publicKeyOptions = {
  	challenge: newChallenge,
    
    rp: {
    	name: 'puppycam',
    },
    
    user: {
    	id: accountId,
      name: 'Angelo',
      displayName: 'angeloliao16@gmail.com'
    },
    
    parameters: [
    	{
      	type: 'public-key',
        algorithm: 'RS256',
      },
      {
      	type: 'public-key',
        algorithm: 'ES256'
      }
    ],
    
    excludeList: [],
    
    authenticatorSelection: {
    	attachment: 'platform'
    },
  };

  const rpId = window.location;
  logClientScriptInfo(rpId, newChallenge);
  
  navigator.credentials.create({'publicKey': publicKeyOptions}).then(function (credInfo) {

    console.log('the info is: ');
    //console.log(credInfo);
    
    validateCreation(credInfo.id, credInfo.rawId, credInfo.response.clientDataJSON, credInfo.response.attestationObject);
  
  });
}

button1.addEventListener('click', function() {
  buttonToBlack(button1);

  createCred();
});


/* Authentication Code */

const verifyPublicKey = function () {
  // 1. Compute the hash of the data. 
  // 2. Decrypt the digital sig using the sender's public key 
  // 3. Compare the 2 hash values. 
};

const serverVerify = function(assertion) {
  // do nothing for now. 
};

const verify = function () {
  const options = {
    challenge: Uint8Array(stringToBytes('Windows Hello')),
  };

  navigator.credentials.get({'publicKey': options}).then(function (assertion) {
    serverVerify(assertion);
  }).catch(function(err) {
    alert('verify error: ${err}');
  });
}

button2.addEventListener('click', function() {
  buttonToGreen(button2);

  verify();
});