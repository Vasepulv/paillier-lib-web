import './style.css'
import {encrypt} from '../target/scala-2.13/paillier-fastopt/encryption.js'


var data=window.location.href.split("?");
data=data[1].split("&");

var length=Number(data[0].split("=")[1]);
var amount=Number(data[1].split("=")[1]);
var lt=Number(data[2].split("=")[1]);
var wt=Number(data[3].split("=")[1]);

document.querySelector('button').addEventListener('click',encryptBrowser)

function encryptBrowser(){
    var toEncrypt=document.getElementById("toEncrypt").value
    console.log(encrypt(toEncrypt,length,amount,lt,wt))
    
}