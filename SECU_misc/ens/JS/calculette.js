// src/libCrypto.ts
async function stringToPublicKeyForEncryption(pkeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(pkeyBase64);
    const key = await window.crypto.subtle.importKey(
      "spki",
      keyArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the public key (for encryption) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the public key (for encryption) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPublicKeyForSignature(pkeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(pkeyBase64);
    const key = await window.crypto.subtle.importKey(
      "spki",
      keyArrayBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      true,
      ["verify"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the public key (for signature verification) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the public key (for signature verification) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPrivateKeyForEncryption(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      keyArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the private key (for decryption) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the private key (for decryption) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPrivateKeyForSignature(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      keyArrayBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      true,
      ["sign"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the private key (for signature) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the private key (for signature) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function publicKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64String(exportedKey);
}
async function privateKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64String(exportedKey);
}
async function generateAssymetricKeysForEncryption() {
  const keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  return [keypair.publicKey, keypair.privateKey];
}
async function generateAssymetricKeysForSignature() {
  const keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  return [keypair.publicKey, keypair.privateKey];
}
function generateNonce() {
  const nonceArray = new Uint32Array(1);
  self.crypto.getRandomValues(nonceArray);
  return nonceArray[0].toString();
}
async function encryptWithPublicKey(publicKey, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const cypheredMessageAB = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      messageToArrayBuffer
    );
    return arrayBufferToBase64String(cypheredMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Encryption failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Public key or message to encrypt is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function signWithPrivateKey(privateKey, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const signedMessageAB = await window.crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      messageToArrayBuffer
    );
    return arrayBufferToBase64String(signedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Signature failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Private key or message to sign is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function decryptWithPrivateKey(privateKey, message) {
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64StringToArrayBuffer(message)
    );
    return arrayBufferToText(decrytpedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for decryption");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Private key or message to decrypt is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage2) {
  try {
    const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage2);
    const messageInClearToArrayBuffer = textToArrayBuffer(messageInClear);
    const verified = await window.crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signedToArrayBuffer,
      messageInClearToArrayBuffer
    );
    return verified;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for signature verification");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Public key or signed message to verify is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function generateSymetricKey() {
  const key = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
  return key;
}
async function symmetricKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64String(exportedKey);
}
async function stringToSymmetricKey(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyArrayBuffer,
      "AES-GCM",
      true,
      ["encrypt", "decrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the symmetric key is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the symmetric key is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function encryptWithSymmetricKey(key, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ivText = arrayBufferToBase64String(iv);
    const cypheredMessageAB = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      messageToArrayBuffer
    );
    return [arrayBufferToBase64String(cypheredMessageAB), ivText];
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Encryption failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Symmetric key or message to encrypt is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function decryptWithSymmetricKey(key, message, initVector) {
  const decodedInitVector = base64StringToArrayBuffer(initVector);
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodedInitVector },
      key,
      base64StringToArrayBuffer(message)
    );
    return arrayBufferToText(decrytpedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for decryption");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Symmetric key or message to decrypt is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function hash(text) {
  const text2arrayBuf = textToArrayBuffer(text);
  const hashedArray = await window.crypto.subtle.digest("SHA-256", text2arrayBuf);
  return arrayBufferToBase64String(hashedArray);
}
var KeyStringCorrupted = class extends Error {
};
function arrayBufferToBase64String(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var byteString = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
}
function base64StringToArrayBuffer(b64str) {
  try {
    var byteStr = atob(b64str);
    var bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.log(`String starting by '${b64str.substring(0, 10)}' cannot be converted to a valid key or message`);
    throw new KeyStringCorrupted();
  }
}
function textToArrayBuffer(str) {
  var buf = encodeURIComponent(str);
  var bufView = new Uint8Array(buf.length);
  for (var i = 0; i < buf.length; i++) {
    bufView[i] = buf.charCodeAt(i);
  }
  return bufView;
}
function arrayBufferToText(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var str = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    str += String.fromCharCode(byteArray[i]);
  }
  return decodeURIComponent(str);
}

// src/calculette.ts
var rsaEncryptButton = document.getElementById("rsa-encrypt-button");
var rsaDecryptButton = document.getElementById("rsa-decrypt-button");
var rsaSignButton = document.getElementById("rsa-sign-button");
var rsaVerifyButton = document.getElementById("rsa-verify-button");
var generateAsymEncKeysButton = document.getElementById("generate-asym-enc-keys-button");
var generateNonceButton = document.getElementById("generate-nonce-button");
var hashButton = document.getElementById("hash-button");
var generateSymKeyButton = document.getElementById("generate-symkey-button");
var aesEncryptButton = document.getElementById("aes-encrypt-button");
var aesDecryptButton = document.getElementById("aes-decrypt-button");
var publicKeyEncElement = document.getElementById("gen-public-key-enc");
var privateKeyEncElement = document.getElementById("gen-private-key-enc");
var publicKeySignElement = document.getElementById("gen-public-key-sign");
var privateKeySignElement = document.getElementById("gen-private-key-sign");
var symmetricKeyElement = document.getElementById("gen-symmetric-key");
var aesKeyEncrypt = document.getElementById("aes-encrypt-key");
var aesKeyDecrypt = document.getElementById("aes-decrypt-key");
var rsaMessageBox = document.getElementById("rsa-oaep-message");
var aesEncryptMessageBox = document.getElementById("aes-encrypt-message");
var aesDecryptMessageBox = document.getElementById("aes-decrypt-message");
var publicKeyEncBox = document.getElementById("rsa-pubkey-enc");
var privateKeyEncBox = document.getElementById("rsa-privkey-enc");
var publicKeySignBox = document.getElementById("rsa-pubkey-sign");
var privateKeySignBox = document.getElementById("rsa-privkey-sign");
var aesEncryptKey = document.getElementById("aes-encrypt-key");
var aesDecryptKey = document.getElementById("aes-decrypt-key");
var cypherTextElement = document.getElementById("cyphertext-value");
var messageToDecryptBox = document.getElementById("message-to-decrypt");
var decypheredTextElement = document.getElementById("decyphertext-value");
var messageToSign = document.getElementById("message-to-sign");
var signedMessage = document.getElementById("signed-value");
var signedMessageToCheck = document.getElementById("signed-message-to-check");
var signedMessageInClear = document.getElementById("signed-message-in-clear");
var rsaPublicKeyForVerification = document.getElementById("rsa-public-sign");
var verificationValue = document.getElementById("verification-value");
var messageToHash = document.getElementById("message-to-hash");
var hashedMessage = document.getElementById("hashed-message");
var aesCypherTextElement = document.getElementById("aes-cyphertext-value");
var aesCypherIV = document.getElementById("aes-cyphertext-IV");
var aesMessageToDecryptBox = document.getElementById("aes-message-to-decrypt");
var aesIVToDecryptBox = document.getElementById("aes-decrypt-IV");
var aesDecypheredTextElement = document.getElementById("aes-decyphertext-value");
var nonceTextElement = document.getElementById("nonce");
generateAsymEncKeysButton.onclick = async function() {
  try {
    const keypair = await generateAssymetricKeysForEncryption();
    const publicKeyText = await publicKeyToString(keypair[0]);
    const privateKeyText = await privateKeyToString(keypair[1]);
    publicKeyEncElement.value = publicKeyText;
    privateKeyEncElement.value = privateKeyText;
  } catch (e) {
    if (e instanceof DOMException) {
      alert("Generation failed!");
    } else {
      alert(e);
    }
  }
};
generateSymKeyButton.onclick = async function() {
  try {
    const key = await generateSymetricKey();
    const keyText = await symmetricKeyToString(key);
    symmetricKeyElement.value = keyText;
  } catch (e) {
    if (e instanceof DOMException) {
      alert("Generation failed!");
    } else {
      alert(e);
    }
  }
};
generateNonceButton.onclick = function() {
  const nonce = generateNonce();
  nonceTextElement.textContent = nonce;
};
hashButton.onclick = async function() {
  const textToHash = messageToHash.value;
  hashedMessage.value = await hash(textToHash);
};
rsaEncryptButton.onclick = async function() {
  try {
    const message = rsaMessageBox.value;
    const publicKeyTextBase64 = publicKeyEncBox.value;
    const publicKey = await stringToPublicKeyForEncryption(publicKeyTextBase64);
    const encryptedMessage = await encryptWithPublicKey(publicKey, message);
    cypherTextElement.value = encryptedMessage;
  } catch (e) {
    alert("Encryption failed!");
  }
};
rsaSignButton.onclick = async function() {
  try {
    const message = messageToSign.value;
    const privateKeyTextBase64 = privateKeySignBox.value;
    const privateKey = await stringToPrivateKeyForSignature(privateKeyTextBase64);
    const resultingSignedMessage = await signWithPrivateKey(privateKey, message);
    signedMessage.value = resultingSignedMessage;
  } catch (e) {
    alert("Signature failed!");
  }
};
rsaVerifyButton.onclick = async function() {
  try {
    const signedMessage2 = signedMessageToCheck.value;
    const messageInClear = signedMessageInClear.value;
    const publicKeyTextBase64 = publicKeySignBox.value;
    const publicKey = await stringToPublicKeyForSignature(publicKeyTextBase64);
    const verification = await verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage2);
    verificationValue.value = "" + verification;
  } catch (e) {
    alert("Signature failed!");
  }
};
aesEncryptButton.onclick = async function() {
  try {
    const message = aesEncryptMessageBox.value;
    const keyTextBase64 = aesEncryptKey.value;
    const key = await stringToSymmetricKey(keyTextBase64);
    const result = await encryptWithSymmetricKey(key, message);
    aesCypherTextElement.value = result[0];
    aesCypherIV.value = result[1];
  } catch (e) {
    alert("Encryption failed!");
  }
};
rsaDecryptButton.onclick = async function() {
  try {
    const message = messageToDecryptBox.value;
    const privateKeyTextBase64 = privateKeyEncBox.value;
    const privateKey = await stringToPrivateKeyForEncryption(privateKeyTextBase64);
    const decryptedMessage = await decryptWithPrivateKey(privateKey, message);
    decypheredTextElement.value = decryptedMessage;
  } catch (e) {
    alert("Decryption failed");
  }
};
aesDecryptButton.onclick = async function() {
  try {
    const message = aesDecryptMessageBox.value;
    const keyTextBase64 = aesDecryptKey.value;
    const key = await stringToSymmetricKey(keyTextBase64);
    const initVector = aesIVToDecryptBox.value;
    const result = await decryptWithSymmetricKey(key, message, initVector);
    aesDecypheredTextElement.value = result;
  } catch (e) {
    alert("Decryption failed!");
  }
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvY2FsY3VsZXR0ZS50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiLyogU291cmNlOiBodHRwczovL2dpc3QuZ2l0aHViLmNvbS9ncm91bmRyYWNlL2I1MTQxMDYyYjQ3ZGQ5NmE1YzIxYzkzODM5ZDRiOTU0ICovXG5cbi8qIEF2YWlsYWJsZSBmdW5jdGlvbnM6XG5cbiAgICAjIEtleS9ub25jZSBnZW5lcmF0aW9uOlxuICAgIGdlbmVyYXRlQXNzeW1ldHJpY0tleXNGb3JFbmNyeXB0aW9uKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvclNpZ25hdHVyZSgpOiBQcm9taXNlPENyeXB0b0tleVtdPlxuICAgIGdlbmVyYXRlU3ltZXRyaWNLZXkoKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmdcblxuICAgICMgQXNzeW1ldHJpYyBrZXkgRW5jcnlwdGlvbi9EZWNyeXB0aW9uL1NpZ25hdHVyZS9TaWduYXR1cmUgdmVyaWZpY2F0aW9uXG4gICAgZW5jcnlwdFdpdGhQdWJsaWNLZXkocGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiAgICBkZWNyeXB0V2l0aFByaXZhdGVLZXkoc2tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzaWduV2l0aFByaXZhdGVLZXkocHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiAgICB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlSW5DbGVhcjogc3RyaW5nLCBzaWduZWRNZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+XG5cbiAgICAjIFN5bW1ldHJpYyBrZXkgRW5jcnlwdGlvbi9EZWNyeXB0aW9uXG4gICAgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nW10+XG4gICAgZGVjcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZywgaW5pdFZlY3Rvcjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+XG5cbiAgICAjIEltcG9ydGluZyBrZXlzIGZyb20gc3RyaW5nXG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKHBrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbihza2V5SW5CYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PlxuICAgIHN0cmluZ1RvUHVibGljS2V5Rm9yU2lnbmF0dXJlKHBrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9TeW1tZXRyaWNLZXkoc2tleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG5cbiAgICAjIEV4cG9ydGluZyBrZXlzIHRvIHN0cmluZ1xuICAgIHB1YmxpY0tleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+XG4gICAgcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+XG4gICAgc3ltbWV0cmljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSGFzaGluZ1xuICAgIGhhc2godGV4dDogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+XG4qL1xuXG4vLyBMaWJDcnlwdG8tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBmcm9tIHRoZSBpbXBvcnQgc3BhY2UuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKHBrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihwa2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwic3BraVwiLFxuICAgICAgICAgICAga2V5QXJyYXlCdWZmZXIsXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbmFtZTogXCJSU0EtT0FFUFwiLFxuICAgICAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHRydWUsXG4gICAgICAgICAgICBbXCJlbmNyeXB0XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHB1YmxpYyBrZXkgKGZvciBzaWduYXR1cmUgdmVyaWZpY2F0aW9uKSBmcm9tIHRoZSBpbXBvcnQgc3BhY2UuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcInZlcmlmeVwiXVxuICAgICAgICApXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBzaWduYXR1cmUgdmVyaWZpY2F0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8qXG5JbXBvcnRzIHRoZSBnaXZlbiBwcml2YXRlIGtleSAoaW4gc3RyaW5nKSBhcyBhIHZhbGlkIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbilcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbihza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2tleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInBrY3M4XCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImRlY3J5cHRcIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInBrY3M4XCIgPz8gZm9ybWF0IGZvciBpbXBvcnRpbmcgcHVibGljIGtleXMuXG4qL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN0cmluZ1RvUHJpdmF0ZUtleUZvclNpZ25hdHVyZShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2tleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInBrY3M4XCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcInNpZ25cIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3Igc2lnbmF0dXJlKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG4vKlxuRXhwb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSBpbnRvIGEgdmFsaWQgc3RyaW5nLlxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJzcGtpXCIgZm9ybWF0IGZvciBleHBvcnRpbmcgcHVibGljIGtleXMuXG4qL1xuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGV4cG9ydGVkS2V5OiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmV4cG9ydEtleShcInNwa2lcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKlxuRXhwb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSBpbnRvIGEgdmFsaWQgc3RyaW5nLlxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJzcGtpXCIgZm9ybWF0IGZvciBleHBvcnRpbmcgcHVibGljIGtleXMuXG4qL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHByaXZhdGVLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwicGtjczhcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3IgZW5jcnlwdGlvbi9kZWNyeXB0aW9uICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT4ge1xuICAgIGNvbnN0IGtleXBhaXI6IENyeXB0b0tleVBhaXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShcbiAgICAgICAge1xuICAgICAgICAgICAgbmFtZTogXCJSU0EtT0FFUFwiLFxuICAgICAgICAgICAgbW9kdWx1c0xlbmd0aDogMjA0OCxcbiAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMSwgMCwgMV0pLFxuICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgIH0sXG4gICAgICAgIHRydWUsXG4gICAgICAgIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcGFpciBvZiBwdWJsaWMgYW5kIHByaXZhdGUgUlNBIGtleXMgZm9yIHNpZ25pbmcvdmVyaWZ5aW5nICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvclNpZ25hdHVyZSgpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wic2lnblwiLCBcInZlcmlmeVwiXVxuICAgIClcbiAgICByZXR1cm4gW2tleXBhaXIucHVibGljS2V5LCBrZXlwYWlyLnByaXZhdGVLZXldXG59XG5cbi8qIEdlbmVyYXRlcyBhIHJhbmRvbSBub25jZSAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdlbmVyYXRlTm9uY2UoKTogc3RyaW5nIHtcbiAgICBjb25zdCBub25jZUFycmF5ID0gbmV3IFVpbnQzMkFycmF5KDEpXG4gICAgc2VsZi5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5vbmNlQXJyYXkpXG4gICAgcmV0dXJuIG5vbmNlQXJyYXlbMF0udG9TdHJpbmcoKVxufVxuXG4vKiBFbmNyeXB0cyBhIG1lc3NhZ2Ugd2l0aCBhIHB1YmxpYyBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBlbmNyeXB0V2l0aFB1YmxpY0tleShwdWJsaWNLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IGN5cGhlcmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmVuY3J5cHQoXG4gICAgICAgICAgICB7IG5hbWU6IFwiUlNBLU9BRVBcIiB9LFxuICAgICAgICAgICAgcHVibGljS2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhjeXBoZXJlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIkVuY3J5cHRpb24gZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJQdWJsaWMga2V5IG9yIG1lc3NhZ2UgdG8gZW5jcnlwdCBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLyogU2lnbiBhIG1lc3NhZ2Ugd2l0aCBhIHByaXZhdGUga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2lnbldpdGhQcml2YXRlS2V5KHByaXZhdGVLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IHNpZ25lZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5zaWduKFxuICAgICAgICAgICAgXCJSU0FTU0EtUEtDUzEtdjFfNVwiLFxuICAgICAgICAgICAgcHJpdmF0ZUtleSxcbiAgICAgICAgICAgIG1lc3NhZ2VUb0FycmF5QnVmZmVyXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoc2lnbmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiU2lnbmF0dXJlIGZhaWxlZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiUHJpdmF0ZSBrZXkgb3IgbWVzc2FnZSB0byBzaWduIGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIERlY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHJpdmF0ZSBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWNyeXB0V2l0aFByaXZhdGVLZXkocHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGRlY3J5dHBlZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdFxuICAgICAgICAgICAgd2luZG93LmNyeXB0by5zdWJ0bGUuZGVjcnlwdChcbiAgICAgICAgICAgICAgICB7IG5hbWU6IFwiUlNBLU9BRVBcIiB9LFxuICAgICAgICAgICAgICAgIHByaXZhdGVLZXksXG4gICAgICAgICAgICAgICAgYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb1RleHQoZGVjcnl0cGVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiSW52YWxpZCBrZXksIG1lc3NhZ2Ugb3IgYWxnb3JpdGhtIGZvciBkZWNyeXB0aW9uXCIpXG4gICAgICAgIH0gZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJQcml2YXRlIGtleSBvciBtZXNzYWdlIHRvIGRlY3J5cHQgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIFZlcmlmaWNhdGlvbiBvZiBhIHNpZ25hdHVyZSBvbiBhIG1lc3NhZ2Ugd2l0aCBhIHB1YmxpYyBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlSW5DbGVhcjogc3RyaW5nLCBzaWduZWRNZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBzaWduZWRUb0FycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihzaWduZWRNZXNzYWdlKVxuICAgICAgICBjb25zdCBtZXNzYWdlSW5DbGVhclRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlSW5DbGVhcilcbiAgICAgICAgY29uc3QgdmVyaWZpZWQ6IGJvb2xlYW4gPSBhd2FpdFxuICAgICAgICAgICAgd2luZG93LmNyeXB0by5zdWJ0bGUudmVyaWZ5KFxuICAgICAgICAgICAgICAgIFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICAgICAgc2lnbmVkVG9BcnJheUJ1ZmZlcixcbiAgICAgICAgICAgICAgICBtZXNzYWdlSW5DbGVhclRvQXJyYXlCdWZmZXIpXG4gICAgICAgIHJldHVybiB2ZXJpZmllZFxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiSW52YWxpZCBrZXksIG1lc3NhZ2Ugb3IgYWxnb3JpdGhtIGZvciBzaWduYXR1cmUgdmVyaWZpY2F0aW9uXCIpXG4gICAgICAgIH0gZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJQdWJsaWMga2V5IG9yIHNpZ25lZCBtZXNzYWdlIHRvIHZlcmlmeSBpcyBpbGwtZm9ybWVkXCIpXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLyogR2VuZXJhdGVzIGEgc3ltbWV0cmljIEFFUy1HQ00ga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiQUVTLUdDTVwiLFxuICAgICAgICAgICAgbGVuZ3RoOiAyNTYsXG4gICAgICAgIH0sXG4gICAgICAgIHRydWUsXG4gICAgICAgIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdXG4gICAgKVxuICAgIHJldHVybiBrZXlcbn1cblxuLyogYSBzeW1tZXRyaWMgQUVTIGtleSBpbnRvIGEgc3RyaW5nICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3ltbWV0cmljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGV4cG9ydGVkS2V5OiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmV4cG9ydEtleShcInJhd1wiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEltcG9ydHMgdGhlIGdpdmVuIGtleSAoaW4gc3RyaW5nKSBhcyBhIHZhbGlkIEFFUyBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2tleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInJhd1wiLFxuICAgICAgICAgICAga2V5QXJyYXlCdWZmZXIsXG4gICAgICAgICAgICBcIkFFUy1HQ01cIixcbiAgICAgICAgICAgIHRydWUsXG4gICAgICAgICAgICBbXCJlbmNyeXB0XCIsIFwiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBzeW1tZXRyaWMga2V5IGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHN5bW1ldHJpYyBrZXkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8vIFdoZW4gY3lwaGVyaW5nIGEgbWVzc2FnZSB3aXRoIGEga2V5IGluIEFFUywgd2Ugb2J0YWluIGEgY3lwaGVyZWQgbWVzc2FnZSBhbmQgYW4gXCJpbml0aWFsaXNhdGlvbiB2ZWN0b3JcIi5cbi8vIEluIHRoaXMgaW1wbGVtZW50YXRpb24sIHRoZSBvdXRwdXQgaXMgYSB0d28gZWxlbWVudHMgYXJyYXkgdCBzdWNoIHRoYXQgdFswXSBpcyB0aGUgY3lwaGVyZWQgbWVzc2FnZVxuLy8gYW5kIHRbMV0gaXMgdGhlIGluaXRpYWxpc2F0aW9uIHZlY3Rvci4gVG8gc2ltcGxpZnksIHRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3IgaXMgcmVwcmVzZW50ZWQgYnkgYSBzdHJpbmcuXG4vLyBUaGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yZSBpcyB1c2VkIGZvciBwcm90ZWN0aW5nIHRoZSBlbmNyeXB0aW9uLCBpLmUsIDIgZW5jcnlwdGlvbnMgb2YgdGhlIHNhbWUgbWVzc2FnZSBcbi8vIHdpdGggdGhlIHNhbWUga2V5IHdpbGwgbmV2ZXIgcmVzdWx0IGludG8gdGhlIHNhbWUgZW5jcnlwdGVkIG1lc3NhZ2UuXG4vLyBcbi8vIE5vdGUgdGhhdCBmb3IgZGVjeXBoZXJpbmcsIHRoZSAqKnNhbWUqKiBpbml0aWFsaXNhdGlvbiB2ZWN0b3Igd2lsbCBiZSBuZWVkZWQuXG4vLyBUaGlzIHZlY3RvciBjYW4gc2FmZWx5IGJlIHRyYW5zZmVycmVkIGluIGNsZWFyIHdpdGggdGhlIGVuY3J5cHRlZCBtZXNzYWdlLlxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nW10+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IGl2ID0gd2luZG93LmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMTIpKTtcbiAgICAgICAgY29uc3QgaXZUZXh0ID0gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhpdilcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJBRVMtR0NNXCIsIGl2IH0sXG4gICAgICAgICAgICBrZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBbYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhjeXBoZXJlZE1lc3NhZ2VBQiksIGl2VGV4dF1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIkVuY3J5cHRpb24gZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTeW1tZXRyaWMga2V5IG9yIG1lc3NhZ2UgdG8gZW5jcnlwdCBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLy8gRm9yIGRlY3lwaGVyaW5nLCB3ZSBuZWVkIHRoZSBrZXksIHRoZSBjeXBoZXJlZCBtZXNzYWdlIGFuZCB0aGUgaW5pdGlhbGl6YXRpb24gdmVjdG9yLiBTZWUgYWJvdmUgdGhlIFxuLy8gY29tbWVudHMgZm9yIHRoZSBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleSBmdW5jdGlvblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlY3J5cHRXaXRoU3ltbWV0cmljS2V5KGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcsIGluaXRWZWN0b3I6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZGVjb2RlZEluaXRWZWN0b3I6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihpbml0VmVjdG9yKVxuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGRlY3J5dHBlZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdFxuICAgICAgICAgICAgd2luZG93LmNyeXB0by5zdWJ0bGUuZGVjcnlwdChcbiAgICAgICAgICAgICAgICB7IG5hbWU6IFwiQUVTLUdDTVwiLCBpdjogZGVjb2RlZEluaXRWZWN0b3IgfSxcbiAgICAgICAgICAgICAgICBrZXksXG4gICAgICAgICAgICAgICAgYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb1RleHQoZGVjcnl0cGVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiSW52YWxpZCBrZXksIG1lc3NhZ2Ugb3IgYWxnb3JpdGhtIGZvciBkZWNyeXB0aW9uXCIpXG4gICAgICAgIH0gZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJTeW1tZXRyaWMga2V5IG9yIG1lc3NhZ2UgdG8gZGVjcnlwdCBpcyBpbGwtZm9ybWVkXCIpXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8vIFNIQS0yNTYgSGFzaCBmcm9tIGEgdGV4dFxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhc2godGV4dDogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCB0ZXh0MmFycmF5QnVmID0gdGV4dFRvQXJyYXlCdWZmZXIodGV4dClcbiAgICBjb25zdCBoYXNoZWRBcnJheSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmRpZ2VzdChcIlNIQS0yNTZcIiwgdGV4dDJhcnJheUJ1ZilcbiAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhoYXNoZWRBcnJheSlcbn1cblxuY2xhc3MgS2V5U3RyaW5nQ29ycnVwdGVkIGV4dGVuZHMgRXJyb3IgeyB9XG5cbi8vIEFycmF5QnVmZmVyIHRvIGEgQmFzZTY0IHN0cmluZ1xuZnVuY3Rpb24gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhhcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICAgIHZhciBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShhcnJheUJ1ZmZlcilcbiAgICB2YXIgYnl0ZVN0cmluZyA9ICcnXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlQXJyYXkuYnl0ZUxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGJ5dGVTdHJpbmcgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlQXJyYXlbaV0pXG4gICAgfVxuICAgIHJldHVybiBidG9hKGJ5dGVTdHJpbmcpXG59XG5cbi8vIEJhc2U2NCBzdHJpbmcgdG8gYW4gYXJyYXlCdWZmZXJcbmZ1bmN0aW9uIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoYjY0c3RyOiBzdHJpbmcpOiBBcnJheUJ1ZmZlciB7XG4gICAgdHJ5IHtcbiAgICAgICAgdmFyIGJ5dGVTdHIgPSBhdG9iKGI2NHN0cilcbiAgICAgICAgdmFyIGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZVN0ci5sZW5ndGgpXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZVN0ci5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgYnl0ZXNbaV0gPSBieXRlU3RyLmNoYXJDb2RlQXQoaSlcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gYnl0ZXMuYnVmZmVyXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhgU3RyaW5nIHN0YXJ0aW5nIGJ5ICcke2I2NHN0ci5zdWJzdHJpbmcoMCwgMTApfScgY2Fubm90IGJlIGNvbnZlcnRlZCB0byBhIHZhbGlkIGtleSBvciBtZXNzYWdlYClcbiAgICAgICAgdGhyb3cgbmV3IEtleVN0cmluZ0NvcnJ1cHRlZFxuICAgIH1cbn1cblxuLy8gU3RyaW5nIHRvIGFycmF5IGJ1ZmZlclxuZnVuY3Rpb24gdGV4dFRvQXJyYXlCdWZmZXIoc3RyOiBzdHJpbmcpOiBBcnJheUJ1ZmZlciB7XG4gICAgdmFyIGJ1ZiA9IGVuY29kZVVSSUNvbXBvbmVudChzdHIpIC8vIDIgYnl0ZXMgZm9yIGVhY2ggY2hhclxuICAgIHZhciBidWZWaWV3ID0gbmV3IFVpbnQ4QXJyYXkoYnVmLmxlbmd0aClcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykge1xuICAgICAgICBidWZWaWV3W2ldID0gYnVmLmNoYXJDb2RlQXQoaSlcbiAgICB9XG4gICAgcmV0dXJuIGJ1ZlZpZXdcbn1cblxuLy8gQXJyYXkgYnVmZmVycyB0byBzdHJpbmdcbmZ1bmN0aW9uIGFycmF5QnVmZmVyVG9UZXh0KGFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gICAgdmFyIGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKVxuICAgIHZhciBzdHIgPSAnJ1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZUFycmF5LmJ5dGVMZW5ndGg7IGkrKykge1xuICAgICAgICBzdHIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlQXJyYXlbaV0pXG4gICAgfVxuICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoc3RyKVxufVxuXG4iLCAiXG4vKiBTb3VyY2U6IGh0dHBzOi8vZ2lzdC5naXRodWIuY29tL2dyb3VuZHJhY2UvYjUxNDEwNjJiNDdkZDk2YTVjMjFjOTM4MzlkNGI5NTQgKi9cblxuLyogdHNjIC0taW5saW5lU291cmNlTWFwIHRydWUgLW91dEZpbGUgSlMvY2FsY3VsZXR0ZS5qcyBzcmMvbGliQ3J5cHRvLnRzIHNyYy9jYWxjdWxldHRlLnRzIC0tdGFyZ2V0IGVzMjAxNSAgKi9cblxuaW1wb3J0IHtcbiAgICBlbmNyeXB0V2l0aFB1YmxpY0tleSwgZGVjcnlwdFdpdGhQcml2YXRlS2V5LFxuICAgIGdlbmVyYXRlU3ltZXRyaWNLZXksIGdlbmVyYXRlTm9uY2UsIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5LCBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleSxcbiAgICBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yRW5jcnlwdGlvbiwgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbiwgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uLCBoYXNoLFxuICAgIHN0cmluZ1RvU3ltbWV0cmljS2V5LCBwdWJsaWNLZXlUb1N0cmluZywgcHJpdmF0ZUtleVRvU3RyaW5nLCBzeW1tZXRyaWNLZXlUb1N0cmluZywgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlLFxuICAgIHN0cmluZ1RvUHVibGljS2V5Rm9yU2lnbmF0dXJlLCBzaWduV2l0aFByaXZhdGVLZXksIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXlcbn0gZnJvbSAnLi9saWJDcnlwdG8nXG5cblxuLyogQXBwbGljYXRpb24gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG5cbi8qIGdldHRpbmcgdGhlIG1haW4gb2JqZWN0cyBmcm9tIHRoZSBkb20gKi9cbi8qIEJ1dHRvbnMgKi9cbmNvbnN0IHJzYUVuY3J5cHRCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInJzYS1lbmNyeXB0LWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuY29uc3QgcnNhRGVjcnlwdEJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicnNhLWRlY3J5cHQtYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCByc2FTaWduQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJyc2Etc2lnbi1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcbmNvbnN0IHJzYVZlcmlmeUJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicnNhLXZlcmlmeS1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcbmNvbnN0IGdlbmVyYXRlQXN5bUVuY0tleXNCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImdlbmVyYXRlLWFzeW0tZW5jLWtleXMtYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG4vL2NvbnN0IGdlbmVyYXRlQXN5bVNpZ25LZXlzQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJnZW5lcmF0ZS1hc3ltLXNpZ24ta2V5cy1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcblxuY29uc3QgZ2VuZXJhdGVOb25jZUJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZ2VuZXJhdGUtbm9uY2UtYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCBoYXNoQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJoYXNoLWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuXG5jb25zdCBnZW5lcmF0ZVN5bUtleUJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZ2VuZXJhdGUtc3lta2V5LWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuY29uc3QgYWVzRW5jcnlwdEJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWVuY3J5cHQtYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCBhZXNEZWNyeXB0QnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJhZXMtZGVjcnlwdC1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcblxuXG4vKiBsYWJlbHMgYW5kIGlucHV0IGZpZWxkcyAqL1xuY29uc3QgcHVibGljS2V5RW5jRWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZ2VuLXB1YmxpYy1rZXktZW5jXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcbmNvbnN0IHByaXZhdGVLZXlFbmNFbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJnZW4tcHJpdmF0ZS1rZXktZW5jXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcbmNvbnN0IHB1YmxpY0tleVNpZ25FbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJnZW4tcHVibGljLWtleS1zaWduXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcbmNvbnN0IHByaXZhdGVLZXlTaWduRWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZ2VuLXByaXZhdGUta2V5LXNpZ25cIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuXG5jb25zdCBzeW1tZXRyaWNLZXlFbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJnZW4tc3ltbWV0cmljLWtleVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBhZXNLZXlFbmNyeXB0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJhZXMtZW5jcnlwdC1rZXlcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgYWVzS2V5RGVjcnlwdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWRlY3J5cHQta2V5XCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcblxuY29uc3QgcnNhTWVzc2FnZUJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicnNhLW9hZXAtbWVzc2FnZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBhZXNFbmNyeXB0TWVzc2FnZUJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWVuY3J5cHQtbWVzc2FnZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBhZXNEZWNyeXB0TWVzc2FnZUJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWRlY3J5cHQtbWVzc2FnZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5cbmNvbnN0IHB1YmxpY0tleUVuY0JveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicnNhLXB1YmtleS1lbmNcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgcHJpdmF0ZUtleUVuY0JveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicnNhLXByaXZrZXktZW5jXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcbmNvbnN0IHB1YmxpY0tleVNpZ25Cb3ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInJzYS1wdWJrZXktc2lnblwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBwcml2YXRlS2V5U2lnbkJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicnNhLXByaXZrZXktc2lnblwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBhZXNFbmNyeXB0S2V5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJhZXMtZW5jcnlwdC1rZXlcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgYWVzRGVjcnlwdEtleSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWRlY3J5cHQta2V5XCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcblxuY29uc3QgY3lwaGVyVGV4dEVsZW1lbnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImN5cGhlcnRleHQtdmFsdWVcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgbWVzc2FnZVRvRGVjcnlwdEJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwibWVzc2FnZS10by1kZWNyeXB0XCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcbmNvbnN0IGRlY3lwaGVyZWRUZXh0RWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZGVjeXBoZXJ0ZXh0LXZhbHVlXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcblxuY29uc3QgbWVzc2FnZVRvU2lnbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwibWVzc2FnZS10by1zaWduXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcbmNvbnN0IHNpZ25lZE1lc3NhZ2UgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInNpZ25lZC12YWx1ZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5cbmNvbnN0IHNpZ25lZE1lc3NhZ2VUb0NoZWNrID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJzaWduZWQtbWVzc2FnZS10by1jaGVja1wiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBzaWduZWRNZXNzYWdlSW5DbGVhciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwic2lnbmVkLW1lc3NhZ2UtaW4tY2xlYXJcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgcnNhUHVibGljS2V5Rm9yVmVyaWZpY2F0aW9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJyc2EtcHVibGljLXNpZ25cIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgdmVyaWZpY2F0aW9uVmFsdWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInZlcmlmaWNhdGlvbi12YWx1ZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5cbmNvbnN0IG1lc3NhZ2VUb0hhc2ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcIm1lc3NhZ2UtdG8taGFzaFwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBoYXNoZWRNZXNzYWdlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJoYXNoZWQtbWVzc2FnZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5cbmNvbnN0IGFlc0N5cGhlclRleHRFbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJhZXMtY3lwaGVydGV4dC12YWx1ZVwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBhZXNDeXBoZXJJViA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWN5cGhlcnRleHQtSVZcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgYWVzTWVzc2FnZVRvRGVjcnlwdEJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLW1lc3NhZ2UtdG8tZGVjcnlwdFwiKSBhcyBIVE1MVGV4dEFyZWFFbGVtZW50XG5jb25zdCBhZXNJVlRvRGVjcnlwdEJveCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiYWVzLWRlY3J5cHQtSVZcIikgYXMgSFRNTFRleHRBcmVhRWxlbWVudFxuY29uc3QgYWVzRGVjeXBoZXJlZFRleHRFbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJhZXMtZGVjeXBoZXJ0ZXh0LXZhbHVlXCIpIGFzIEhUTUxUZXh0QXJlYUVsZW1lbnRcblxuY29uc3Qgbm9uY2VUZXh0RWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwibm9uY2VcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuXG5nZW5lcmF0ZUFzeW1FbmNLZXlzQnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5W10gPSBhd2FpdCBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yRW5jcnlwdGlvbigpXG4gICAgICAgIGNvbnN0IHB1YmxpY0tleVRleHQgPSBhd2FpdCBwdWJsaWNLZXlUb1N0cmluZyhrZXlwYWlyWzBdKVxuICAgICAgICBjb25zdCBwcml2YXRlS2V5VGV4dCA9IGF3YWl0IHByaXZhdGVLZXlUb1N0cmluZyhrZXlwYWlyWzFdKVxuICAgICAgICBwdWJsaWNLZXlFbmNFbGVtZW50LnZhbHVlID0gcHVibGljS2V5VGV4dFxuICAgICAgICBwcml2YXRlS2V5RW5jRWxlbWVudC52YWx1ZSA9IHByaXZhdGVLZXlUZXh0XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBhbGVydChcIkdlbmVyYXRpb24gZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBhbGVydChlKSB9XG4gICAgfVxufVxuXG4vLyBnZW5lcmF0ZUFzeW1TaWduS2V5c0J1dHRvbi5vbmNsaWNrID0gYXN5bmMgZnVuY3Rpb24gKCkge1xuLy8gICAgIHRyeSB7XG4vLyAgICAgICAgIGNvbnN0IGtleXBhaXI6IENyeXB0b0tleVtdID0gYXdhaXQgZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvclNpZ25hdHVyZSgpXG4vLyAgICAgICAgIGNvbnN0IHB1YmxpY0tleVRleHQgPSBhd2FpdCBwdWJsaWNLZXlUb1N0cmluZyhrZXlwYWlyWzBdKVxuLy8gICAgICAgICBjb25zdCBwcml2YXRlS2V5VGV4dCA9IGF3YWl0IHByaXZhdGVLZXlUb1N0cmluZyhrZXlwYWlyWzFdKVxuLy8gICAgICAgICBwdWJsaWNLZXlTaWduRWxlbWVudC52YWx1ZSA9IHB1YmxpY0tleVRleHRcbi8vICAgICAgICAgcHJpdmF0ZUtleVNpZ25FbGVtZW50LnZhbHVlID0gcHJpdmF0ZUtleVRleHRcbi8vICAgICB9IGNhdGNoIChlKSB7XG4vLyAgICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGFsZXJ0KFwiR2VuZXJhdGlvbiBmYWlsZWQhXCIpIH1cbi8vICAgICAgICAgZWxzZSB7IGFsZXJ0KGUpIH1cbi8vICAgICB9XG4vLyB9XG5cbmdlbmVyYXRlU3ltS2V5QnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCBnZW5lcmF0ZVN5bWV0cmljS2V5KClcbiAgICAgICAgY29uc3Qga2V5VGV4dCA9IGF3YWl0IHN5bW1ldHJpY0tleVRvU3RyaW5nKGtleSlcbiAgICAgICAgc3ltbWV0cmljS2V5RWxlbWVudC52YWx1ZSA9IGtleVRleHRcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGFsZXJ0KFwiR2VuZXJhdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGFsZXJ0KGUpIH1cbiAgICB9XG59XG5cbmdlbmVyYXRlTm9uY2VCdXR0b24ub25jbGljayA9IGZ1bmN0aW9uICgpIHtcbiAgICBjb25zdCBub25jZSA9IGdlbmVyYXRlTm9uY2UoKVxuICAgIG5vbmNlVGV4dEVsZW1lbnQudGV4dENvbnRlbnQgPSBub25jZVxufVxuXG5oYXNoQnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgY29uc3QgdGV4dFRvSGFzaCA9IG1lc3NhZ2VUb0hhc2gudmFsdWVcbiAgICBoYXNoZWRNZXNzYWdlLnZhbHVlID0gYXdhaXQgaGFzaCh0ZXh0VG9IYXNoKVxufVxuXG5yc2FFbmNyeXB0QnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZSA9IHJzYU1lc3NhZ2VCb3gudmFsdWVcbiAgICAgICAgY29uc3QgcHVibGljS2V5VGV4dEJhc2U2NDogc3RyaW5nID0gcHVibGljS2V5RW5jQm94LnZhbHVlXG4gICAgICAgIGNvbnN0IHB1YmxpY0tleTogQ3J5cHRvS2V5ID0gYXdhaXQgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKHB1YmxpY0tleVRleHRCYXNlNjQpXG4gICAgICAgIGNvbnN0IGVuY3J5cHRlZE1lc3NhZ2U6IHN0cmluZyA9IGF3YWl0IGVuY3J5cHRXaXRoUHVibGljS2V5KHB1YmxpY0tleSwgbWVzc2FnZSlcbiAgICAgICAgY3lwaGVyVGV4dEVsZW1lbnQudmFsdWUgPSBlbmNyeXB0ZWRNZXNzYWdlXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBhbGVydChcIkVuY3J5cHRpb24gZmFpbGVkIVwiKVxuICAgIH1cbn1cblxucnNhU2lnbkJ1dHRvbi5vbmNsaWNrID0gYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBtZXNzYWdlVG9TaWduLnZhbHVlXG4gICAgICAgIGNvbnN0IHByaXZhdGVLZXlUZXh0QmFzZTY0OiBzdHJpbmcgPSBwcml2YXRlS2V5U2lnbkJveC52YWx1ZVxuICAgICAgICBjb25zdCBwcml2YXRlS2V5OiBDcnlwdG9LZXkgPSBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUocHJpdmF0ZUtleVRleHRCYXNlNjQpXG4gICAgICAgIGNvbnN0IHJlc3VsdGluZ1NpZ25lZE1lc3NhZ2U6IHN0cmluZyA9IGF3YWl0IHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5LCBtZXNzYWdlKVxuICAgICAgICBzaWduZWRNZXNzYWdlLnZhbHVlID0gcmVzdWx0aW5nU2lnbmVkTWVzc2FnZVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgYWxlcnQoXCJTaWduYXR1cmUgZmFpbGVkIVwiKVxuICAgIH1cbn1cblxuXG5yc2FWZXJpZnlCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBzaWduZWRNZXNzYWdlID0gc2lnbmVkTWVzc2FnZVRvQ2hlY2sudmFsdWVcbiAgICAgICAgY29uc3QgbWVzc2FnZUluQ2xlYXIgPSBzaWduZWRNZXNzYWdlSW5DbGVhci52YWx1ZVxuICAgICAgICBjb25zdCBwdWJsaWNLZXlUZXh0QmFzZTY0OiBzdHJpbmcgPSBwdWJsaWNLZXlTaWduQm94LnZhbHVlXG4gICAgICAgIGNvbnN0IHB1YmxpY0tleTogQ3J5cHRvS2V5ID0gYXdhaXQgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocHVibGljS2V5VGV4dEJhc2U2NClcbiAgICAgICAgY29uc3QgdmVyaWZpY2F0aW9uOiBib29sZWFuID0gYXdhaXQgdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleShwdWJsaWNLZXksIG1lc3NhZ2VJbkNsZWFyLCBzaWduZWRNZXNzYWdlKVxuICAgICAgICB2ZXJpZmljYXRpb25WYWx1ZS52YWx1ZSA9IFwiXCIgKyB2ZXJpZmljYXRpb25cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGFsZXJ0KFwiU2lnbmF0dXJlIGZhaWxlZCFcIilcbiAgICB9XG59XG5cbmFlc0VuY3J5cHRCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlID0gYWVzRW5jcnlwdE1lc3NhZ2VCb3gudmFsdWVcbiAgICAgICAgY29uc3Qga2V5VGV4dEJhc2U2NDogc3RyaW5nID0gYWVzRW5jcnlwdEtleS52YWx1ZVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHN0cmluZ1RvU3ltbWV0cmljS2V5KGtleVRleHRCYXNlNjQpXG4gICAgICAgIGNvbnN0IHJlc3VsdDogc3RyaW5nW10gPSBhd2FpdCBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXksIG1lc3NhZ2UpXG4gICAgICAgIGFlc0N5cGhlclRleHRFbGVtZW50LnZhbHVlID0gcmVzdWx0WzBdXG4gICAgICAgIGFlc0N5cGhlcklWLnZhbHVlID0gcmVzdWx0WzFdXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBhbGVydChcIkVuY3J5cHRpb24gZmFpbGVkIVwiKVxuICAgIH1cbn1cblxucnNhRGVjcnlwdEJ1dHRvbi5vbmNsaWNrID0gYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBtZXNzYWdlVG9EZWNyeXB0Qm94LnZhbHVlXG4gICAgICAgIGNvbnN0IHByaXZhdGVLZXlUZXh0QmFzZTY0OiBzdHJpbmcgPSBwcml2YXRlS2V5RW5jQm94LnZhbHVlXG4gICAgICAgIGNvbnN0IHByaXZhdGVLZXk6IENyeXB0b0tleSA9IGF3YWl0IHN0cmluZ1RvUHJpdmF0ZUtleUZvckVuY3J5cHRpb24ocHJpdmF0ZUtleVRleHRCYXNlNjQpXG4gICAgICAgIGNvbnN0IGRlY3J5cHRlZE1lc3NhZ2U6IHN0cmluZyA9IGF3YWl0IGRlY3J5cHRXaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5LCBtZXNzYWdlKVxuICAgICAgICBkZWN5cGhlcmVkVGV4dEVsZW1lbnQudmFsdWUgPSBkZWNyeXB0ZWRNZXNzYWdlXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBhbGVydChcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgfVxufVxuXG5cbmFlc0RlY3J5cHRCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlID0gYWVzRGVjcnlwdE1lc3NhZ2VCb3gudmFsdWVcbiAgICAgICAgY29uc3Qga2V5VGV4dEJhc2U2NDogc3RyaW5nID0gYWVzRGVjcnlwdEtleS52YWx1ZVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHN0cmluZ1RvU3ltbWV0cmljS2V5KGtleVRleHRCYXNlNjQpXG4gICAgICAgIGNvbnN0IGluaXRWZWN0b3I6IHN0cmluZyA9IGFlc0lWVG9EZWNyeXB0Qm94LnZhbHVlXG4gICAgICAgIGNvbnN0IHJlc3VsdDogc3RyaW5nID0gYXdhaXQgZGVjcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5LCBtZXNzYWdlLCBpbml0VmVjdG9yKVxuICAgICAgICBhZXNEZWN5cGhlcmVkVGV4dEVsZW1lbnQudmFsdWUgPSByZXN1bHRcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGFsZXJ0KFwiRGVjcnlwdGlvbiBmYWlsZWQhXCIpXG4gICAgfVxufSJdLAogICJtYXBwaW5ncyI6ICI7QUEwQ0EsZUFBc0IsK0JBQStCLFlBQXdDO0FBQ3pGLE1BQUk7QUFDQSxVQUFNLGlCQUE4QiwwQkFBMEIsVUFBVTtBQUN4RSxVQUFNLE1BQWlC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QW1CLFlBQVksT0FBTztBQUNuRixrQkFBYyxRQUFRO0FBQUEsRUFDMUIsU0FBUyxHQUFHO0FBQ1IsVUFBTSxtQkFBbUI7QUFBQSxFQUM3QjtBQUNKO0FBR0EsZ0JBQWdCLFVBQVUsaUJBQWtCO0FBQ3hDLE1BQUk7QUFDQSxVQUFNQyxpQkFBZ0IscUJBQXFCO0FBQzNDLFVBQU0saUJBQWlCLHFCQUFxQjtBQUM1QyxVQUFNLHNCQUE4QixpQkFBaUI7QUFDckQsVUFBTSxZQUF1QixNQUFNLDhCQUE4QixtQkFBbUI7QUFDcEYsVUFBTSxlQUF3QixNQUFNLDZCQUE2QixXQUFXLGdCQUFnQkEsY0FBYTtBQUN6RyxzQkFBa0IsUUFBUSxLQUFLO0FBQUEsRUFDbkMsU0FBUyxHQUFHO0FBQ1IsVUFBTSxtQkFBbUI7QUFBQSxFQUM3QjtBQUNKO0FBRUEsaUJBQWlCLFVBQVUsaUJBQWtCO0FBQ3pDLE1BQUk7QUFDQSxVQUFNLFVBQVUscUJBQXFCO0FBQ3JDLFVBQU0sZ0JBQXdCLGNBQWM7QUFDNUMsVUFBTSxNQUFpQixNQUFNLHFCQUFxQixhQUFhO0FBQy9ELFVBQU0sU0FBbUIsTUFBTSx3QkFBd0IsS0FBSyxPQUFPO0FBQ25FLHlCQUFxQixRQUFRLE9BQU8sQ0FBQztBQUNyQyxnQkFBWSxRQUFRLE9BQU8sQ0FBQztBQUFBLEVBQ2hDLFNBQVMsR0FBRztBQUNSLFVBQU0sb0JBQW9CO0FBQUEsRUFDOUI7QUFDSjtBQUVBLGlCQUFpQixVQUFVLGlCQUFrQjtBQUN6QyxNQUFJO0FBQ0EsVUFBTSxVQUFVLG9CQUFvQjtBQUNwQyxVQUFNLHVCQUErQixpQkFBaUI7QUFDdEQsVUFBTSxhQUF3QixNQUFNLGdDQUFnQyxvQkFBb0I7QUFDeEYsVUFBTSxtQkFBMkIsTUFBTSxzQkFBc0IsWUFBWSxPQUFPO0FBQ2hGLDBCQUFzQixRQUFRO0FBQUEsRUFDbEMsU0FBUyxHQUFHO0FBQ1IsVUFBTSxtQkFBbUI7QUFBQSxFQUM3QjtBQUNKO0FBR0EsaUJBQWlCLFVBQVUsaUJBQWtCO0FBQ3pDLE1BQUk7QUFDQSxVQUFNLFVBQVUscUJBQXFCO0FBQ3JDLFVBQU0sZ0JBQXdCLGNBQWM7QUFDNUMsVUFBTSxNQUFpQixNQUFNLHFCQUFxQixhQUFhO0FBQy9ELFVBQU0sYUFBcUIsa0JBQWtCO0FBQzdDLFVBQU0sU0FBaUIsTUFBTSx3QkFBd0IsS0FBSyxTQUFTLFVBQVU7QUFDN0UsNkJBQXlCLFFBQVE7QUFBQSxFQUNyQyxTQUFTLEdBQUc7QUFDUixVQUFNLG9CQUFvQjtBQUFBLEVBQzlCO0FBQ0o7IiwKICAibmFtZXMiOiBbInNpZ25lZE1lc3NhZ2UiLCAic2lnbmVkTWVzc2FnZSJdCn0K
