var button1 = document.getElementById('test1')
button1.style.color = 'blue';

const buttonToBlack = function(button) {
  button.style.color = 'black';
}

// Convert ArrayBuffer to UTF-8 string. 
const ab2str = function (buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
};

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

  decodeAuthData(authData);
  console.log(decoded);
};

const decodeAuthData = function (authData) {

  // I counted the length of everything and compared them to the event viewer. They almost add up. 
  const rpIdHash = authData.slice(0, 31);

  // The flags added up perfectly. It should say the AT and TUP flags are both 1 and the rest are 0. 
  const flags = authData.slice(32);
  const counter = authData.slice(33, 36);
  const authDataByteLength = authData.byteLength; 
  const authDataLength = authData.length;
  const attestationData = authData.slice(36, authDataLength - 1);

  decodeAttestData(attestationData);
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

const validateCreation = function (id, rawId, clientData, attestationObj) {
  // May have to stringify here
  localStorage.setItem('id', id);
  localStorage.setItem('rawId', rawId);
	decodeClientData(clientData);
  decodeAttestationObj(attestationObj);
;}

const createCred = function() {
	var publicKeyOptions = {
  	challenge: new Uint8Array(stringToBytes('Windows Hello')),
    
    rp: {
    	name: 'puppycam',
    },
    
    user: {
    	id: 1234,
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
  
  navigator.credentials.create({'publicKey': publicKeyOptions}).then(function (credInfo) {

    console.log('the info is: ');
    //console.log(credInfo);
    
    validateCreation(credInfo.id, credInfo.rawId, credInfo.response.clientDataJSON, credInfo.response.attestationObject);
  
  });
}

button1.addEventListener('click', function() {
  buttonToBlack(button1);
  //button1.innerHTML = 'hello';
  
  var initial = { Hello: "World" };
	var encoded = CBOR.encode(initial);
	var decoded = CBOR.decode(encoded);
  
  console.log(decoded.Hello);
  
  button1.innerHTML = decoded.Hello; 
  
  createCred();
});
