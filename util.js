// Convert ArrayBuffer to UTF-8 string. 
// This should really be taken out once TextEncoder is shipped. 
const ab2str = function (buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
};

// Convert from hex to binary
// E.g. from 41 to 01000001
const hexToBinary = function (s) {
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

const buf2hex = function (buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

const hexstr2uint8 = function (hexStr) {
  var uint8 = new Uint8Array(hexStr.match(/[\da-f]{2}/gi).map(function (h) {
    return parseInt(h, 16)
  }));

  return uint8;
};

const concatArrBuffer = function (buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer2.byteLength);
    return tmp.buffer;
};

function arrayBufferToBase64(buffer) {
    var binaryStr = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binaryStr += String.fromCharCode( bytes[ i ] );
    }
    return btoa( binaryStr );
}