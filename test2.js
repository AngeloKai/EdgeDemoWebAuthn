/*
  The below demo app is coded against the 5th Working Draft of the Web Authentication API: 
    https://www.w3.org/TR/2017/WD-webauthn-20170505/
*/
if (!PublicKeyCredential) {
  alert('navigator.credentials.create namespace does not exist');
}

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

/*
 Client Side Functions: 
  - createCred 
  - verify
*/

const logClientScriptInfo = function(stage, rpId, challenge) {
  const origin = window.location.hostname;
  localStorage.setItem(stage + '_ClientSide_Origin', origin);

  localStorage.setItem(stage + '_ClientSide_RpId', rpId);

  const challengeStr = new TextDecoder().decode(challenge);
  localStorage.setItem(stage + '_ClientSide_ChallengeStr', challengeStr);

};

const createCredPerAcct = function() {
  const rpName =  'puppycam';
  const accountName = 'Angelo';
  const accountDisplayName = 'angeloliao16@gmail.com';
  const authnrOption = {
    attachment: 'platform',
  };
  createCred(rpName, accountId, accountName, accountDisplayName, authnrOption);
};

const createCred = function(rpName, accountId, accountName, accountDisplayName, authnrOption) {
  const newChallenge = new TextEncoder().encode('Windows Hello');
  //const newChallenge = new Uint8Array(stringToBytes('Windows Hello'));

	var publicKeyOptions = {
  	challenge: newChallenge,
    
    rp: {
    	name: rpName,
    },
    
    user: {
      // accountId needs to be unique per account. 
    	id: accountId,
      name: accountName,
      displayName: accountDisplayName,
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
    
    authenticatorSelection: authnrOption,
  };

  const rpId = window.location.hostname;
  logClientScriptInfo('createCred', rpId, newChallenge);
  
  navigator.credentials.create({'publicKey': publicKeyOptions}).then(function (credInfo) {
    
    return serverRegisterCred(accountId, accountName, accountDisplayName, credInfo.id, 
      credInfo.rawId, credInfo.response.clientDataJSON, credInfo.response.attestationObject);
  
  }).then(function(bool){
    return bool;
  }).catch(function(err) {
    console.log(err);
  });
}


const verify = function () {
  const options = {
    challenge: new Uint8Array(stringToBytes('CTAP')),
  };

  const rpId = window.location.hostname;
  logClientScriptInfo(rpId, newChallenge);

  navigator.credentials.get({'publicKey': options}).then(function (assertion) {
    serverVerify(assertion);
  }).catch(function(err) {
    alert('verify error: ${err}');
  });
}

/* 
  Add Event Listener 
*/

button1.addEventListener('click', function() {
  buttonToBlack(button1);

  createCredPerAcct();
});

button2.addEventListener('click', function() {
  buttonToGreen(button2);

  verify();
});
