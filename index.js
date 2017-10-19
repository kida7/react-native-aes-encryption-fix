import React, { NativeModules } from 'react-native';

var aes = NativeModules.ReactAES;
var base64 = require('base-64')



var reactAES = function () { }
reactAES.encrypt = async function (data, key, iv) {
    return base64.decode(await aes.encrypt(data, key, base64.encode(iv)));
}

reactAES.decrypt = async function (data, key, iv) {
    return await aes.decrypt(base64.encode(data), key, base64.encode(iv));
}

reactAES.generateRandomIV = async function (length) {
    return await aes.base64.decode(aes.generateRandomIV(length));
}
reactAES.createMac = async function (data, key) {
    return await aes.createMac(base64.encode(data), key);
}


module.exports = reactAES;