import React, { NativeModules } from 'react-native';
var aes = NativeModules.ReactAES;
var base64 = require('base-64')

export async function encrypt(data, key, iv){
    return await aes.encrypt(data,key, base64.encode(iv));
}

export async function decrypt(data, key, iv){
    return await aes.decrypt(base64.encode(data),key, base64.encode(iv));
}

export async function generateRandomIV(){
    return await aes.generateRandomIV();
}