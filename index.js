import React, { NativeModules } from 'react-native';

var aes = NativeModules.ReactAES;
var base64 = require('base-64')



class ReactAES{
    async encrypt(data, key, iv){
        return await aes.encrypt(data,key, base64.encode(iv));
    }
    
    async decrypt(data, key, iv){
        return await aes.decrypt(base64.encode(data),key, base64.encode(iv));
    }
    
    async generateRandomIV(){
        return await aes.base64.decode(aes.generateRandomIV());
    }
    async createMac(data, key){
        return await aes.createMac(base64.encode(data),key);
    }
}

module.exports = ReactAES;