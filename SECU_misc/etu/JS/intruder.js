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
async function verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage) {
  try {
    const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage);
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

// src/serverMessages.ts
var CasUserName = class {
  constructor(username) {
    this.username = username;
  }
};
var HistoryRequest = class {
  constructor(agentName, index) {
    this.agentName = agentName;
    this.index = index;
  }
};
var HistoryAnswer = class {
  constructor(success, failureMessage, index, allMessages) {
    this.success = success;
    this.failureMessage = failureMessage;
    this.index = index;
    this.allMessages = allMessages;
  }
};
var FilterRequest = class {
  constructor(from2, to2, indexmin) {
    this.from = from2;
    this.to = to2;
    this.indexmin = indexmin;
  }
};
var FilteredMessage = class {
  constructor(message, index, deleted, deleter) {
    this.message = message;
    this.index = index;
    this.deleted = deleted;
    this.deleter = deleter;
  }
};
var FilteringAnswer = class {
  constructor(success, failureMessage, allMessages) {
    this.success = success;
    this.failureMessage = failureMessage;
    this.allMessages = allMessages;
  }
};
var SendResult = class {
  constructor(success, errorMessage) {
    this.success = success;
    this.errorMessage = errorMessage;
  }
};
var ExtMessage = class {
  constructor(sender, receiver, content) {
    this.sender = sender;
    this.receiver = receiver;
    this.content = content;
  }
};
var DeletingRequest = class {
  constructor(indexToDelete) {
    this.indexToDelete = indexToDelete;
  }
};
var DeletingAnswer = class {
  constructor(success, message) {
    this.success = success;
  }
};
var KeyRequest = class {
  constructor(ownerOfTheKey, publicKey, encryption) {
    this.ownerOfTheKey = ownerOfTheKey;
    this.publicKey = publicKey;
    this.encryption = encryption;
  }
};
var KeyResult = class {
  constructor(success, key, errorMessage) {
    this.success = success;
    this.key = key;
    this.errorMessage = errorMessage;
  }
};

// src/intruder.ts
var filterButton = document.getElementById("filter-button");
var sendButton = document.getElementById("send-button");
var deleteButton = document.getElementById("delete-button");
var getPublicKeyButton = document.getElementById("get-public-key-button");
var getPrivateKeyButton = document.getElementById("get-private-key-button");
var generateNonceButton = document.getElementById("generate-nonce-button");
var public_key_owner = document.getElementById("public-key-owner");
var private_key_owner = document.getElementById("private-key-owner");
var publicKeyElementEnc = document.getElementById("public-key-enc");
var privateKeyElementEnc = document.getElementById("private-key-enc");
var publicKeyElementSign = document.getElementById("public-key-sign");
var privateKeyElementSign = document.getElementById("private-key-sign");
var nonceTextElement = document.getElementById("nonce");
var from = document.getElementById("from");
var to = document.getElementById("to");
var indexminElt = document.getElementById("indexmin");
var filtered_messages = document.getElementById("filtered-messages");
var sendfrom = document.getElementById("sendfrom");
var sendto = document.getElementById("sendto");
var sendcontent = document.getElementById("sendcontent");
var deleteIndex = document.getElementById("deleteindex");
async function fetchCasName() {
  const urlParams = new URLSearchParams(window.location.search);
  const namerequest = await fetch("/getuser?" + urlParams, {
    method: "GET",
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  });
  if (!namerequest.ok) {
    throw new Error(`Error! status: ${namerequest.status}`);
  }
  const nameResult = await namerequest.json();
  return nameResult.username;
}
async function setCasName() {
  public_key_owner.value = await fetchCasName();
  private_key_owner.value = await fetchCasName();
}
setCasName();
function getOwnerName() {
  const path = window.location.pathname;
  const name = path.split("/", 2)[1];
  return name;
}
var ownerName = getOwnerName();
function clearingMessages() {
  filtered_messages.textContent = "";
}
function stringToHTML(str) {
  var div_elt = document.createElement("div");
  div_elt.innerHTML = str;
  return div_elt;
}
function addingFilteredMessage(message) {
  filtered_messages.append(stringToHTML("<p></p><p></p>" + message));
}
generateNonceButton.onclick = function() {
  const nonce = generateNonce();
  nonceTextElement.textContent = nonce;
};
async function fetchKey(user, publicKey, encryption) {
  const keyRequestMessage = new KeyRequest(user, publicKey, encryption);
  const urlParams = new URLSearchParams(window.location.search);
  const keyrequest = await fetch("/getKey?" + urlParams, {
    method: "POST",
    body: JSON.stringify(keyRequestMessage),
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  });
  if (!keyrequest.ok) {
    throw new Error(`Error! status: ${keyrequest.status}`);
  }
  const keyResult = await keyrequest.json();
  if (!keyResult.success) alert(keyResult.errorMessage);
  else {
    if (publicKey) return await stringToPublicKeyForEncryption(keyResult.key);
    else return await stringToPrivateKeyForEncryption(keyResult.key);
  }
}
getPublicKeyButton.onclick = async function() {
  const public_key_owner_name = public_key_owner.value;
  const publicKeyEnc = await fetchKey(public_key_owner_name, true, true);
  const publicKeySign = await fetchKey(public_key_owner_name, true, false);
  publicKeyElementEnc.textContent = await publicKeyToString(publicKeyEnc);
  publicKeyElementSign.textContent = await publicKeyToString(publicKeySign);
};
getPrivateKeyButton.onclick = async function() {
  const private_key_owner_name = private_key_owner.value;
  const privateKeyEnc = await fetchKey(private_key_owner_name, false, true);
  const privateKeySign = await fetchKey(private_key_owner_name, false, false);
  privateKeyElementEnc.textContent = await privateKeyToString(privateKeyEnc);
  privateKeyElementSign.textContent = await privateKeyToString(privateKeySign);
};
deleteButton.onclick = async function() {
  let indexToDelete = deleteIndex.value;
  const urlParams = new URLSearchParams(window.location.search);
  try {
    let deleteRequest = new DeletingRequest(indexToDelete);
    const request = await fetch("/deleting/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(deleteRequest),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    return await request.json();
  } catch (error) {
    if (error instanceof Error) {
      alert(error.message);
      return new DeletingAnswer(false, error.message);
    } else {
      console.log("unexpected error: ", error);
      return new DeletingAnswer(false, "An unexpected error occurred");
    }
  }
};
async function sendMessage(agentName, receiverName, messageContent) {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/intruderSendingMessage/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(messageToSend),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    return await request.json();
  } catch (error) {
    if (error instanceof Error) {
      console.log(error.message);
      return new SendResult(false, error.message);
    } else {
      console.log(error);
      return new SendResult(false, "An unexpected error occurred");
    }
  }
}
sendButton.onclick = async function() {
  let agentName = sendfrom.value;
  let receiverName = sendto.value;
  let content = sendcontent.value;
  try {
    const sendResult = await sendMessage(agentName, receiverName, content);
    if (!sendResult.success) alert(sendResult.errorMessage);
    else {
      console.log("Successfully sent the message!");
    }
  } catch (e) {
    if (e instanceof Error) {
      console.log(e.message);
    } else {
      console.log(e);
    }
  }
};
filterButton.onclick = async function() {
  try {
    const fromText = from.value;
    const toText = to.value;
    const indexmin = indexminElt.value;
    const filterRequest = new FilterRequest(fromText, toText, indexmin);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/filtering/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(filterRequest),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    const result = await request.json();
    if (!result.success) {
      alert(result.failureMessage);
    } else {
      clearingMessages();
      for (var filt_message of result.allMessages) {
        if (filt_message.deleted) {
          addingFilteredMessage(`Index: ${filt_message.index} Deleted by: ${filt_message.deleter} <strike> From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content} </strike>`);
        } else {
          addingFilteredMessage(`Index: ${filt_message.index} From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content}`);
        }
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      console.log("error message: ", error.message);
      return error.message;
    } else {
      console.log("unexpected error: ", error);
      return "An unexpected error occurred";
    }
  }
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvc2VydmVyTWVzc2FnZXMudHMiLCAiLi4vc3JjL2ludHJ1ZGVyLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBTb3VyY2U6IGh0dHBzOi8vZ2lzdC5naXRodWIuY29tL2dyb3VuZHJhY2UvYjUxNDEwNjJiNDdkZDk2YTVjMjFjOTM4MzlkNGI5NTQgKi9cblxuLyogQXZhaWxhYmxlIGZ1bmN0aW9uczpcblxuICAgICMgS2V5L25vbmNlIGdlbmVyYXRpb246XG4gICAgZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT5cbiAgICBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBnZW5lcmF0ZU5vbmNlKCk6IHN0cmluZ1xuXG4gICAgIyBBc3N5bWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb24vU2lnbmF0dXJlL1NpZ25hdHVyZSB2ZXJpZmljYXRpb25cbiAgICBlbmNyeXB0V2l0aFB1YmxpY0tleShwa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShza2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj5cblxuICAgICMgU3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb25cbiAgICBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT5cbiAgICBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSW1wb3J0aW5nIGtleXMgZnJvbSBzdHJpbmdcbiAgICBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoc2tleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cblxuICAgICMgRXhwb3J0aW5nIGtleXMgdG8gc3RyaW5nXG4gICAgcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBwcml2YXRlS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPlxuXG4gICAgIyBIYXNoaW5nXG4gICAgaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiovXG5cbi8vIExpYkNyeXB0by0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIl1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShwa2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIocGtleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInNwa2lcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1widmVyaWZ5XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKVxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJwa2NzOFwiID8/IGZvcm1hdCBmb3IgaW1wb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBLU9BRVBcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHJpdmF0ZSBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSlcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wic2lnblwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwdWJsaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwic3BraVwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEdlbmVyYXRlcyBhIHBhaXIgb2YgcHVibGljIGFuZCBwcml2YXRlIFJTQSBrZXlzIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yRW5jcnlwdGlvbigpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIFtrZXlwYWlyLnB1YmxpY0tleSwga2V5cGFpci5wcml2YXRlS2V5XVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3Igc2lnbmluZy92ZXJpZnlpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+IHtcbiAgICBjb25zdCBrZXlwYWlyOiBDcnlwdG9LZXlQYWlyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IDIwNDgsXG4gICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzEsIDAsIDFdKSxcbiAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJzaWduXCIsIFwidmVyaWZ5XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcmFuZG9tIG5vbmNlICovXG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmcge1xuICAgIGNvbnN0IG5vbmNlQXJyYXkgPSBuZXcgVWludDMyQXJyYXkoMSlcbiAgICBzZWxmLmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobm9uY2VBcnJheSlcbiAgICByZXR1cm4gbm9uY2VBcnJheVswXS50b1N0cmluZygpXG59XG5cbi8qIEVuY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKiBTaWduIGEgbWVzc2FnZSB3aXRoIGEgcHJpdmF0ZSBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzaWduV2l0aFByaXZhdGVLZXkocHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3Qgc2lnbmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLnNpZ24oXG4gICAgICAgICAgICBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICBwcml2YXRlS2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhzaWduZWRNZXNzYWdlQUIpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhlKTsgY29uc29sZS5sb2coXCJTaWduYXR1cmUgZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJQcml2YXRlIGtleSBvciBtZXNzYWdlIHRvIHNpZ24gaXMgaWxsLWZvcm1lZFwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLyogRGVjcnlwdHMgYSBtZXNzYWdlIHdpdGggYSBwcml2YXRlIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgZGVjcnl0cGVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0XG4gICAgICAgICAgICB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kZWNyeXB0KFxuICAgICAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICAgICAgcHJpdmF0ZUtleSxcbiAgICAgICAgICAgICAgICBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvVGV4dChkZWNyeXRwZWRNZXNzYWdlQUIpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJJbnZhbGlkIGtleSwgbWVzc2FnZSBvciBhbGdvcml0aG0gZm9yIGRlY3J5cHRpb25cIilcbiAgICAgICAgfSBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlByaXZhdGUga2V5IG9yIG1lc3NhZ2UgdG8gZGVjcnlwdCBpcyBpbGwtZm9ybWVkXCIpXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLyogVmVyaWZpY2F0aW9uIG9mIGEgc2lnbmF0dXJlIG9uIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHNpZ25lZFRvQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHNpZ25lZE1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IG1lc3NhZ2VJbkNsZWFyVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2VJbkNsZWFyKVxuICAgICAgICBjb25zdCB2ZXJpZmllZDogYm9vbGVhbiA9IGF3YWl0XG4gICAgICAgICAgICB3aW5kb3cuY3J5cHRvLnN1YnRsZS52ZXJpZnkoXG4gICAgICAgICAgICAgICAgXCJSU0FTU0EtUEtDUzEtdjFfNVwiLFxuICAgICAgICAgICAgICAgIHB1YmxpY0tleSxcbiAgICAgICAgICAgICAgICBzaWduZWRUb0FycmF5QnVmZmVyLFxuICAgICAgICAgICAgICAgIG1lc3NhZ2VJbkNsZWFyVG9BcnJheUJ1ZmZlcilcbiAgICAgICAgcmV0dXJuIHZlcmlmaWVkXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJJbnZhbGlkIGtleSwgbWVzc2FnZSBvciBhbGdvcml0aG0gZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb25cIilcbiAgICAgICAgfSBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3Igc2lnbmVkIG1lc3NhZ2UgdG8gdmVyaWZ5IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBHZW5lcmF0ZXMgYSBzeW1tZXRyaWMgQUVTLUdDTSBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVN5bWV0cmljS2V5KCk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShcbiAgICAgICAge1xuICAgICAgICAgICAgbmFtZTogXCJBRVMtR0NNXCIsXG4gICAgICAgICAgICBsZW5ndGg6IDI1NixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIGtleVxufVxuXG4vKiBhIHN5bW1ldHJpYyBBRVMga2V5IGludG8gYSBzdHJpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwicmF3XCIsIGtleSlcbiAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhleHBvcnRlZEtleSlcbn1cblxuLyogSW1wb3J0cyB0aGUgZ2l2ZW4ga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgQUVTIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN0cmluZ1RvU3ltbWV0cmljS2V5KHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicmF3XCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIFwiQUVTLUdDTVwiLFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHN5bW1ldHJpYyBrZXkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgc3ltbWV0cmljIGtleSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLy8gV2hlbiBjeXBoZXJpbmcgYSBtZXNzYWdlIHdpdGggYSBrZXkgaW4gQUVTLCB3ZSBvYnRhaW4gYSBjeXBoZXJlZCBtZXNzYWdlIGFuZCBhbiBcImluaXRpYWxpc2F0aW9uIHZlY3RvclwiLlxuLy8gSW4gdGhpcyBpbXBsZW1lbnRhdGlvbiwgdGhlIG91dHB1dCBpcyBhIHR3byBlbGVtZW50cyBhcnJheSB0IHN1Y2ggdGhhdCB0WzBdIGlzIHRoZSBjeXBoZXJlZCBtZXNzYWdlXG4vLyBhbmQgdFsxXSBpcyB0aGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yLiBUbyBzaW1wbGlmeSwgdGhlIGluaXRpYWxpc2F0aW9uIHZlY3RvciBpcyByZXByZXNlbnRlZCBieSBhIHN0cmluZy5cbi8vIFRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3JlIGlzIHVzZWQgZm9yIHByb3RlY3RpbmcgdGhlIGVuY3J5cHRpb24sIGkuZSwgMiBlbmNyeXB0aW9ucyBvZiB0aGUgc2FtZSBtZXNzYWdlIFxuLy8gd2l0aCB0aGUgc2FtZSBrZXkgd2lsbCBuZXZlciByZXN1bHQgaW50byB0aGUgc2FtZSBlbmNyeXB0ZWQgbWVzc2FnZS5cbi8vIFxuLy8gTm90ZSB0aGF0IGZvciBkZWN5cGhlcmluZywgdGhlICoqc2FtZSoqIGluaXRpYWxpc2F0aW9uIHZlY3RvciB3aWxsIGJlIG5lZWRlZC5cbi8vIFRoaXMgdmVjdG9yIGNhbiBzYWZlbHkgYmUgdHJhbnNmZXJyZWQgaW4gY2xlYXIgd2l0aCB0aGUgZW5jcnlwdGVkIG1lc3NhZ2UuXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgaXYgPSB3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSgxMikpO1xuICAgICAgICBjb25zdCBpdlRleHQgPSBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGl2KVxuICAgICAgICBjb25zdCBjeXBoZXJlZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5lbmNyeXB0KFxuICAgICAgICAgICAgeyBuYW1lOiBcIkFFUy1HQ01cIiwgaXYgfSxcbiAgICAgICAgICAgIGtleSxcbiAgICAgICAgICAgIG1lc3NhZ2VUb0FycmF5QnVmZmVyXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIFthcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKSwgaXZUZXh0XVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN5bW1ldHJpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vLyBGb3IgZGVjeXBoZXJpbmcsIHdlIG5lZWQgdGhlIGtleSwgdGhlIGN5cGhlcmVkIG1lc3NhZ2UgYW5kIHRoZSBpbml0aWFsaXphdGlvbiB2ZWN0b3IuIFNlZSBhYm92ZSB0aGUgXG4vLyBjb21tZW50cyBmb3IgdGhlIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5IGZ1bmN0aW9uXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVjcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZywgaW5pdFZlY3Rvcjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBkZWNvZGVkSW5pdFZlY3RvcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKGluaXRWZWN0b3IpXG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgZGVjcnl0cGVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0XG4gICAgICAgICAgICB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kZWNyeXB0KFxuICAgICAgICAgICAgICAgIHsgbmFtZTogXCJBRVMtR0NNXCIsIGl2OiBkZWNvZGVkSW5pdFZlY3RvciB9LFxuICAgICAgICAgICAgICAgIGtleSxcbiAgICAgICAgICAgICAgICBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvVGV4dChkZWNyeXRwZWRNZXNzYWdlQUIpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJJbnZhbGlkIGtleSwgbWVzc2FnZSBvciBhbGdvcml0aG0gZm9yIGRlY3J5cHRpb25cIilcbiAgICAgICAgfSBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlN5bW1ldHJpYyBrZXkgb3IgbWVzc2FnZSB0byBkZWNyeXB0IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLy8gU0hBLTI1NiBIYXNoIGZyb20gYSB0ZXh0XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHRleHQyYXJyYXlCdWYgPSB0ZXh0VG9BcnJheUJ1ZmZlcih0ZXh0KVxuICAgIGNvbnN0IGhhc2hlZEFycmF5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZGlnZXN0KFwiU0hBLTI1NlwiLCB0ZXh0MmFycmF5QnVmKVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGhhc2hlZEFycmF5KVxufVxuXG5jbGFzcyBLZXlTdHJpbmdDb3JydXB0ZWQgZXh0ZW5kcyBFcnJvciB7IH1cblxuLy8gQXJyYXlCdWZmZXIgdG8gYSBCYXNlNjQgc3RyaW5nXG5mdW5jdGlvbiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gICAgdmFyIGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKVxuICAgIHZhciBieXRlU3RyaW5nID0gJydcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVBcnJheS5ieXRlTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnl0ZVN0cmluZyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGVBcnJheVtpXSlcbiAgICB9XG4gICAgcmV0dXJuIGJ0b2EoYnl0ZVN0cmluZylcbn1cblxuLy8gQmFzZTY0IHN0cmluZyB0byBhbiBhcnJheUJ1ZmZlclxuZnVuY3Rpb24gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihiNjRzdHI6IHN0cmluZyk6IEFycmF5QnVmZmVyIHtcbiAgICB0cnkge1xuICAgICAgICB2YXIgYnl0ZVN0ciA9IGF0b2IoYjY0c3RyKVxuICAgICAgICB2YXIgYnl0ZXMgPSBuZXcgVWludDhBcnJheShieXRlU3RyLmxlbmd0aClcbiAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlU3RyLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBieXRlc1tpXSA9IGJ5dGVTdHIuY2hhckNvZGVBdChpKVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBieXRlcy5idWZmZXJcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBTdHJpbmcgc3RhcnRpbmcgYnkgJyR7YjY0c3RyLnN1YnN0cmluZygwLCAxMCl9JyBjYW5ub3QgYmUgY29udmVydGVkIHRvIGEgdmFsaWQga2V5IG9yIG1lc3NhZ2VgKVxuICAgICAgICB0aHJvdyBuZXcgS2V5U3RyaW5nQ29ycnVwdGVkXG4gICAgfVxufVxuXG4vLyBTdHJpbmcgdG8gYXJyYXkgYnVmZmVyXG5mdW5jdGlvbiB0ZXh0VG9BcnJheUJ1ZmZlcihzdHI6IHN0cmluZyk6IEFycmF5QnVmZmVyIHtcbiAgICB2YXIgYnVmID0gZW5jb2RlVVJJQ29tcG9uZW50KHN0cikgLy8gMiBieXRlcyBmb3IgZWFjaCBjaGFyXG4gICAgdmFyIGJ1ZlZpZXcgPSBuZXcgVWludDhBcnJheShidWYubGVuZ3RoKVxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnVmLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGJ1ZlZpZXdbaV0gPSBidWYuY2hhckNvZGVBdChpKVxuICAgIH1cbiAgICByZXR1cm4gYnVmVmlld1xufVxuXG4vLyBBcnJheSBidWZmZXJzIHRvIHN0cmluZ1xuZnVuY3Rpb24gYXJyYXlCdWZmZXJUb1RleHQoYXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgICB2YXIgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpXG4gICAgdmFyIHN0ciA9ICcnXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlQXJyYXkuYnl0ZUxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHN0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGVBcnJheVtpXSlcbiAgICB9XG4gICAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudChzdHIpXG59XG5cbiIsICIvLyBBbGwgbWVzc2FnZSB0eXBlcyBiZXR3ZWVuIHRoZSBhcHBsaWNhdGlvbiBhbmQgdGhlIHNlcnZlclxuLy8gTWVzc2FnZSBmb3IgdXNlciBuYW1lXG5leHBvcnQgY2xhc3MgQ2FzVXNlck5hbWUge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyB1c2VybmFtZTogc3RyaW5nKSB7IH1cbn1cblxuXG4vLyBNZXNzYWdlIGZvciByZXF1aXJpbmcgaGlzdG9yeVxuZXhwb3J0IGNsYXNzIEhpc3RvcnlSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgYWdlbnROYW1lOiBzdHJpbmcsIHB1YmxpYyBpbmRleDogbnVtYmVyKSB7IH1cbn1cblxuLy8gUmVzdWx0IG9mIGhpc3RvcnkgcmVxdWVzdFxuZXhwb3J0IGNsYXNzIEhpc3RvcnlBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBwdWJsaWMgZmFpbHVyZU1lc3NhZ2U6IHN0cmluZyxcbiAgICAgICAgcHVibGljIGluZGV4OiBudW1iZXIsXG4gICAgICAgIHB1YmxpYyBhbGxNZXNzYWdlczogRXh0TWVzc2FnZVtdKSB7IH1cbn1cblxuLy8gRmlsdGVyaW5nIG9mIG1lc3NhZ2VzXG5leHBvcnQgY2xhc3MgRmlsdGVyUmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIGZyb206IHN0cmluZywgcHVibGljIHRvOiBzdHJpbmcsIHB1YmxpYyBpbmRleG1pbjogc3RyaW5nKSB7IH1cbn1cblxuZXhwb3J0IGNsYXNzIEZpbHRlcmVkTWVzc2FnZSB7XG4gICAgY29uc3RydWN0b3IocHVibGljIG1lc3NhZ2U6IEV4dE1lc3NhZ2UsXG4gICAgICAgIHB1YmxpYyBpbmRleDogbnVtYmVyLFxuICAgICAgICBwdWJsaWMgZGVsZXRlZDogYm9vbGVhbixcbiAgICAgICAgcHVibGljIGRlbGV0ZXI6IHN0cmluZykgeyB9XG59XG5cbi8vIFJlc3VsdCBvZiBmaWx0ZXJpbmcgcmVxdWVzdFxuZXhwb3J0IGNsYXNzIEZpbHRlcmluZ0Fuc3dlciB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sXG4gICAgICAgIHB1YmxpYyBmYWlsdXJlTWVzc2FnZTogc3RyaW5nLFxuICAgICAgICBwdWJsaWMgYWxsTWVzc2FnZXM6IEZpbHRlcmVkTWVzc2FnZVtdKSB7IH1cbn1cblxuLy8gU2VuZGluZyBhIG1lc3NhZ2UgUmVzdWx0IGZvcm1hdFxuZXhwb3J0IGNsYXNzIFNlbmRSZXN1bHQge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLCBwdWJsaWMgZXJyb3JNZXNzYWdlOiBzdHJpbmcpIHsgfVxufVxuXG4vLyBTZW5kaW5nIG1lc3NhZ2VzXG4vLyBUaGUgbWVzc2FnZSBmb3JtYXRcbmV4cG9ydCBjbGFzcyBFeHRNZXNzYWdlIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc2VuZGVyOiBzdHJpbmcsIHB1YmxpYyByZWNlaXZlcjogc3RyaW5nLCBwdWJsaWMgY29udGVudDogc3RyaW5nKSB7IH1cbn1cblxuZXhwb3J0IGNsYXNzIERlbGV0aW5nUmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IoXG4gICAgICAgIHB1YmxpYyBpbmRleFRvRGVsZXRlOiBzdHJpbmcpIHsgfVxufVxuXG5leHBvcnQgY2xhc3MgRGVsZXRpbmdBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBtZXNzYWdlOiBzdHJpbmcpIHsgfVxufVxuXG4vLyBSZXF1ZXN0aW5nIGtleXNcbmV4cG9ydCBjbGFzcyBLZXlSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgb3duZXJPZlRoZUtleTogc3RyaW5nLCBwdWJsaWMgcHVibGljS2V5OiBib29sZWFuLCBwdWJsaWMgZW5jcnlwdGlvbjogYm9vbGVhbikgeyB9XG59XG5cbmV4cG9ydCBjbGFzcyBLZXlSZXN1bHQge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLCBwdWJsaWMga2V5OiBzdHJpbmcsIHB1YmxpYyBlcnJvck1lc3NhZ2U6IHN0cmluZykgeyB9XG59IiwgIi8qIHRzYyAtLWlubGluZVNvdXJjZU1hcCB0cnVlIC1vdXRGaWxlIEpTL2ludHJ1ZGVyLmpzIHNyYy9saWJDcnlwdG8udHMgc3JjL2ludHJ1ZGVyLnRzIC0tdGFyZ2V0IGVzMjAxNSAqL1xuXG5pbXBvcnQge1xuICAgIGdlbmVyYXRlTm9uY2UsXG4gICAgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbiwgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uLFxuICAgIHB1YmxpY0tleVRvU3RyaW5nLCBwcml2YXRlS2V5VG9TdHJpbmcsIHN0cmluZ1RvUHJpdmF0ZUtleUZvclNpZ25hdHVyZSxcbiAgICBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZSxcbn0gZnJvbSAnLi9saWJDcnlwdG8nXG5cbmltcG9ydCB7XG4gICAgRGVsZXRpbmdSZXF1ZXN0LCBEZWxldGluZ0Fuc3dlciwgRmlsdGVyUmVxdWVzdCwgRmlsdGVyaW5nQW5zd2VyLCBLZXlSZXF1ZXN0LFxuICAgIEtleVJlc3VsdCwgQ2FzVXNlck5hbWUsIEV4dE1lc3NhZ2UsIFNlbmRSZXN1bHRcbn0gZnJvbSAnLi9zZXJ2ZXJNZXNzYWdlcydcblxuY29uc3QgZmlsdGVyQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJmaWx0ZXItYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCBzZW5kQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJzZW5kLWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuY29uc3QgZGVsZXRlQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJkZWxldGUtYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCBnZXRQdWJsaWNLZXlCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImdldC1wdWJsaWMta2V5LWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuY29uc3QgZ2V0UHJpdmF0ZUtleUJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZ2V0LXByaXZhdGUta2V5LWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuXG5jb25zdCBnZW5lcmF0ZU5vbmNlQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJnZW5lcmF0ZS1ub25jZS1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcblxuY29uc3QgcHVibGljX2tleV9vd25lciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicHVibGljLWtleS1vd25lclwiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5jb25zdCBwcml2YXRlX2tleV9vd25lciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicHJpdmF0ZS1rZXktb3duZXJcIikgYXMgSFRNTElucHV0RWxlbWVudFxuXG5jb25zdCBwdWJsaWNLZXlFbGVtZW50RW5jID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJwdWJsaWMta2V5LWVuY1wiKSBhcyBIVE1MTGFiZWxFbGVtZW50XG5jb25zdCBwcml2YXRlS2V5RWxlbWVudEVuYyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwicHJpdmF0ZS1rZXktZW5jXCIpIGFzIEhUTUxMYWJlbEVsZW1lbnRcbmNvbnN0IHB1YmxpY0tleUVsZW1lbnRTaWduID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJwdWJsaWMta2V5LXNpZ25cIikgYXMgSFRNTExhYmVsRWxlbWVudFxuY29uc3QgcHJpdmF0ZUtleUVsZW1lbnRTaWduID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJwcml2YXRlLWtleS1zaWduXCIpIGFzIEhUTUxMYWJlbEVsZW1lbnRcblxuY29uc3Qgbm9uY2VUZXh0RWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwibm9uY2VcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuXG5jb25zdCBmcm9tID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJmcm9tXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHRvID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJ0b1wiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5jb25zdCBpbmRleG1pbkVsdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiaW5kZXhtaW5cIikgYXMgSFRNTElucHV0RWxlbWVudFxuY29uc3QgZmlsdGVyZWRfbWVzc2FnZXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImZpbHRlcmVkLW1lc3NhZ2VzXCIpIGFzIEhUTUxMYWJlbEVsZW1lbnRcblxuY29uc3Qgc2VuZGZyb20gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInNlbmRmcm9tXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHNlbmR0byA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwic2VuZHRvXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHNlbmRjb250ZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJzZW5kY29udGVudFwiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5jb25zdCBkZWxldGVJbmRleCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZGVsZXRlaW5kZXhcIikgYXMgSFRNTElucHV0RWxlbWVudFxuXG5hc3luYyBmdW5jdGlvbiBmZXRjaENhc05hbWUoKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCB1cmxQYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpO1xuICAgIGNvbnN0IG5hbWVyZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvZ2V0dXNlcj9cIiArIHVybFBhcmFtcywge1xuICAgICAgICBtZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgIH1cbiAgICB9KTtcbiAgICBpZiAoIW5hbWVyZXF1ZXN0Lm9rKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtuYW1lcmVxdWVzdC5zdGF0dXN9YCk7XG4gICAgfVxuICAgIGNvbnN0IG5hbWVSZXN1bHQgPSAoYXdhaXQgbmFtZXJlcXVlc3QuanNvbigpKSBhcyBDYXNVc2VyTmFtZTtcbiAgICByZXR1cm4gbmFtZVJlc3VsdC51c2VybmFtZVxufVxuXG4vLyBXZSBzZXQgdGhlIGRlZmF1bHQgQ0FTIG5hbWUgZm9yIHRoZSBwdWJsaWMga2V5IGZpZWxkc1xuYXN5bmMgZnVuY3Rpb24gc2V0Q2FzTmFtZSgpIHtcbiAgICBwdWJsaWNfa2V5X293bmVyLnZhbHVlID0gYXdhaXQgZmV0Y2hDYXNOYW1lKClcbiAgICBwcml2YXRlX2tleV9vd25lci52YWx1ZSA9IGF3YWl0IGZldGNoQ2FzTmFtZSgpXG59XG5zZXRDYXNOYW1lKClcblxuLyogTmFtZSBvZiB0aGUgb3duZXIvZGV2ZWxvcHBlciBvZiB0aGUgYXBwbGljYXRpb24sIGkuZSwgdGhlIG5hbWUgb2YgdGhlIGZvbGRlciBcbiAgIHdoZXJlIHRoZSB3ZWIgcGFnZSBvZiB0aGUgYXBwbGljYXRpb24gaXMgc3RvcmVkLiBFLmcsIGZvciB0ZWFjaGVycycgYXBwbGljYXRpb25cbiAgIHRoaXMgbmFtZSBpcyBcImVuc1wiICovXG5cbmZ1bmN0aW9uIGdldE93bmVyTmFtZSgpOiBzdHJpbmcge1xuICAgIGNvbnN0IHBhdGggPSB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWVcbiAgICBjb25zdCBuYW1lID0gcGF0aC5zcGxpdChcIi9cIiwgMilbMV1cbiAgICByZXR1cm4gbmFtZVxufVxuXG5sZXQgb3duZXJOYW1lID0gZ2V0T3duZXJOYW1lKClcblxuZnVuY3Rpb24gY2xlYXJpbmdNZXNzYWdlcygpIHtcbiAgICBmaWx0ZXJlZF9tZXNzYWdlcy50ZXh0Q29udGVudCA9IFwiXCJcbn1cblxuZnVuY3Rpb24gc3RyaW5nVG9IVE1MKHN0cjogc3RyaW5nKTogSFRNTERpdkVsZW1lbnQge1xuICAgIHZhciBkaXZfZWx0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2JylcbiAgICBkaXZfZWx0LmlubmVySFRNTCA9IHN0clxuICAgIHJldHVybiBkaXZfZWx0XG59XG5cbmZ1bmN0aW9uIGFkZGluZ0ZpbHRlcmVkTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpIHtcbiAgICBmaWx0ZXJlZF9tZXNzYWdlcy5hcHBlbmQoc3RyaW5nVG9IVE1MKCc8cD48L3A+PHA+PC9wPicgKyBtZXNzYWdlKSlcbn1cblxuZ2VuZXJhdGVOb25jZUJ1dHRvbi5vbmNsaWNrID0gZnVuY3Rpb24gKCkge1xuICAgIGNvbnN0IG5vbmNlID0gZ2VuZXJhdGVOb25jZSgpXG4gICAgbm9uY2VUZXh0RWxlbWVudC50ZXh0Q29udGVudCA9IG5vbmNlXG59XG5cbmFzeW5jIGZ1bmN0aW9uIGZldGNoS2V5KHVzZXI6IHN0cmluZywgcHVibGljS2V5OiBib29sZWFuLCBlbmNyeXB0aW9uOiBib29sZWFuKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICAvLyBHZXR0aW5nIHRoZSBwdWJsaWMvcHJpdmF0ZSBrZXkgb2YgdXNlci4gXG4gICAgLy8gRm9yIHB1YmxpYyBrZXkgdGhlIGJvb2xlYW4gJ3B1YmxpY0tleScgaXMgdHJ1ZS5cbiAgICAvLyBGb3IgcHJpdmF0ZSBrZXkgdGhlIGJvb2xlYW4gJ3B1YmxpY0tleScgaXMgZmFsc2UuXG4gICAgLy8gSWYgdGhlIGtleSBpcyB1c2VkIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gdGhlbiB0aGUgYm9vbGVhbiAnZW5jcnlwdGlvbicgaXMgdHJ1ZS5cbiAgICAvLyBJZiB0aGUga2V5IGlzIHVzZWQgZm9yIHNpZ25hdHVyZS9zaWduYXR1cmUgdmVyaWZpY2F0aW9uIHRoZW4gdGhlIGJvb2xlYW4gaXMgZmFsc2UuXG4gICAgY29uc3Qga2V5UmVxdWVzdE1lc3NhZ2UgPVxuICAgICAgICBuZXcgS2V5UmVxdWVzdCh1c2VyLCBwdWJsaWNLZXksIGVuY3J5cHRpb24pXG4gICAgLy8gRm9yIENBUyBhdXRoZW50aWNhdGlvbiB3ZSBuZWVkIHRvIGFkZCB0aGUgYXV0aGVudGljYXRpb24gdGlja2V0XG4gICAgLy8gSXQgaXMgY29udGFpbmVkIGluIHVybFBhcmFtc1xuICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgLy8gRm9yIGdldHRpbmcgYSBrZXkgd2UgZG8gbm90IG5lZWQgdGhlIG93bmVyTmFtZSBwYXJhbVxuICAgIC8vIEJlY2F1c2Uga2V5cyBhcmUgaW5kZXBlbmRhbnQgb2YgdGhlIGFwcGxpY2F0aW9uc1xuICAgIGNvbnN0IGtleXJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9nZXRLZXk/XCIgKyB1cmxQYXJhbXMsIHtcbiAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoa2V5UmVxdWVzdE1lc3NhZ2UpLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICB9XG4gICAgfSk7XG4gICAgaWYgKCFrZXlyZXF1ZXN0Lm9rKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtrZXlyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICB9XG4gICAgY29uc3Qga2V5UmVzdWx0ID0gKGF3YWl0IGtleXJlcXVlc3QuanNvbigpKSBhcyBLZXlSZXN1bHQ7XG4gICAgaWYgKCFrZXlSZXN1bHQuc3VjY2VzcykgYWxlcnQoa2V5UmVzdWx0LmVycm9yTWVzc2FnZSlcbiAgICBlbHNlIHtcbiAgICAgICAgaWYgKHB1YmxpY0tleSkgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbihrZXlSZXN1bHQua2V5KVxuICAgICAgICBlbHNlIHJldHVybiBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKGtleVJlc3VsdC5rZXkpXG4gICAgfVxufVxuXG5nZXRQdWJsaWNLZXlCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICBjb25zdCBwdWJsaWNfa2V5X293bmVyX25hbWUgPSBwdWJsaWNfa2V5X293bmVyLnZhbHVlXG4gICAgY29uc3QgcHVibGljS2V5RW5jID0gYXdhaXQgZmV0Y2hLZXkocHVibGljX2tleV9vd25lcl9uYW1lLCB0cnVlLCB0cnVlKVxuICAgIGNvbnN0IHB1YmxpY0tleVNpZ24gPSBhd2FpdCBmZXRjaEtleShwdWJsaWNfa2V5X293bmVyX25hbWUsIHRydWUsIGZhbHNlKVxuICAgIHB1YmxpY0tleUVsZW1lbnRFbmMudGV4dENvbnRlbnQgPSBhd2FpdCBwdWJsaWNLZXlUb1N0cmluZyhwdWJsaWNLZXlFbmMpXG4gICAgcHVibGljS2V5RWxlbWVudFNpZ24udGV4dENvbnRlbnQgPSBhd2FpdCBwdWJsaWNLZXlUb1N0cmluZyhwdWJsaWNLZXlTaWduKVxufVxuXG5nZXRQcml2YXRlS2V5QnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgY29uc3QgcHJpdmF0ZV9rZXlfb3duZXJfbmFtZSA9IHByaXZhdGVfa2V5X293bmVyLnZhbHVlXG4gICAgY29uc3QgcHJpdmF0ZUtleUVuYyA9IGF3YWl0IGZldGNoS2V5KHByaXZhdGVfa2V5X293bmVyX25hbWUsIGZhbHNlLCB0cnVlKVxuICAgIGNvbnN0IHByaXZhdGVLZXlTaWduID0gYXdhaXQgZmV0Y2hLZXkocHJpdmF0ZV9rZXlfb3duZXJfbmFtZSwgZmFsc2UsIGZhbHNlKVxuICAgIHByaXZhdGVLZXlFbGVtZW50RW5jLnRleHRDb250ZW50ID0gYXdhaXQgcHJpdmF0ZUtleVRvU3RyaW5nKHByaXZhdGVLZXlFbmMpXG4gICAgcHJpdmF0ZUtleUVsZW1lbnRTaWduLnRleHRDb250ZW50ID0gYXdhaXQgcHJpdmF0ZUtleVRvU3RyaW5nKHByaXZhdGVLZXlTaWduKVxufVxuXG5kZWxldGVCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICBsZXQgaW5kZXhUb0RlbGV0ZSA9IGRlbGV0ZUluZGV4LnZhbHVlXG4gICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcbiAgICB0cnkge1xuICAgICAgICBsZXQgZGVsZXRlUmVxdWVzdCA9XG4gICAgICAgICAgICBuZXcgRGVsZXRpbmdSZXF1ZXN0KGluZGV4VG9EZWxldGUpXG4gICAgICAgIGNvbnN0IHJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9kZWxldGluZy9cIiArIG93bmVyTmFtZSArIFwiP1wiICsgdXJsUGFyYW1zLCB7XG4gICAgICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoZGVsZXRlUmVxdWVzdCksXG4gICAgICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIGlmICghcmVxdWVzdC5vaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke3JlcXVlc3Quc3RhdHVzfWApO1xuICAgICAgICB9XG4gICAgICAgIC8vIERlYWxpbmcgd2l0aCB0aGUgYW5zd2VyIG9mIHRoZSBtZXNzYWdlIHNlcnZlclxuICAgICAgICByZXR1cm4gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBEZWxldGluZ0Fuc3dlclxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGFsZXJ0KGVycm9yLm1lc3NhZ2UpXG4gICAgICAgICAgICAvL2NvbnNvbGUubG9nKCdlcnJvciBtZXNzYWdlOiAnLCBlcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIHJldHVybiBuZXcgRGVsZXRpbmdBbnN3ZXIoZmFsc2UsIGVycm9yLm1lc3NhZ2UpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygndW5leHBlY3RlZCBlcnJvcjogJywgZXJyb3IpO1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBEZWxldGluZ0Fuc3dlcihmYWxzZSwgJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnKVxuICAgICAgICB9XG4gICAgfVxuXG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNlbmRNZXNzYWdlKGFnZW50TmFtZTogc3RyaW5nLCByZWNlaXZlck5hbWU6IHN0cmluZywgbWVzc2FnZUNvbnRlbnQ6IHN0cmluZyk6IFByb21pc2U8U2VuZFJlc3VsdD4ge1xuICAgIHRyeSB7XG4gICAgICAgIGxldCBtZXNzYWdlVG9TZW5kID0gbmV3IEV4dE1lc3NhZ2UoYWdlbnROYW1lLCByZWNlaXZlck5hbWUsIG1lc3NhZ2VDb250ZW50KVxuICAgICAgICBjb25zdCB1cmxQYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpO1xuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvaW50cnVkZXJTZW5kaW5nTWVzc2FnZS9cIiArIG93bmVyTmFtZSArIFwiP1wiICsgdXJsUGFyYW1zLCB7XG4gICAgICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkobWVzc2FnZVRvU2VuZCksXG4gICAgICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIGlmICghcmVxdWVzdC5vaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke3JlcXVlc3Quc3RhdHVzfWApO1xuICAgICAgICB9XG4gICAgICAgIC8vIERlYWxpbmcgd2l0aCB0aGUgYW5zd2VyIG9mIHRoZSBtZXNzYWdlIHNlcnZlclxuICAgICAgICByZXR1cm4gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBTZW5kUmVzdWx0XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBFcnJvcikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coZXJyb3IubWVzc2FnZSlcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2VuZFJlc3VsdChmYWxzZSwgZXJyb3IubWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKGVycm9yKVxuICAgICAgICAgICAgcmV0dXJuIG5ldyBTZW5kUmVzdWx0KGZhbHNlLCAnQW4gdW5leHBlY3RlZCBlcnJvciBvY2N1cnJlZCcpXG4gICAgICAgIH1cbiAgICB9XG59XG5cbi8vIHRoZSBpbnRydWRlciBzZW5kcyBhIG1lc3NhZ2UgaW4gcGxhY2Ugb2YgYW55IHVzZXJcbnNlbmRCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICBsZXQgYWdlbnROYW1lID0gc2VuZGZyb20udmFsdWVcbiAgICBsZXQgcmVjZWl2ZXJOYW1lID0gc2VuZHRvLnZhbHVlXG4gICAgbGV0IGNvbnRlbnQgPSBzZW5kY29udGVudC52YWx1ZVxuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHNlbmRSZXN1bHQgPSBhd2FpdCBzZW5kTWVzc2FnZShhZ2VudE5hbWUsIHJlY2VpdmVyTmFtZSwgY29udGVudClcbiAgICAgICAgaWYgKCFzZW5kUmVzdWx0LnN1Y2Nlc3MpIGFsZXJ0KHNlbmRSZXN1bHQuZXJyb3JNZXNzYWdlKVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU3VjY2Vzc2Z1bGx5IHNlbnQgdGhlIG1lc3NhZ2UhXCIpXG4gICAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKGUubWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKGUpXG4gICAgICAgIH1cbiAgICB9XG59XG5cbmZpbHRlckJ1dHRvbi5vbmNsaWNrID0gYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGZyb21UZXh0ID0gZnJvbS52YWx1ZVxuICAgICAgICBjb25zdCB0b1RleHQgPSB0by52YWx1ZVxuICAgICAgICBjb25zdCBpbmRleG1pbiA9IGluZGV4bWluRWx0LnZhbHVlXG4gICAgICAgIGNvbnN0IGZpbHRlclJlcXVlc3QgPVxuICAgICAgICAgICAgbmV3IEZpbHRlclJlcXVlc3QoZnJvbVRleHQsIHRvVGV4dCwgaW5kZXhtaW4pXG4gICAgICAgIC8vIEZvciBDQVMgYXV0aGVudGljYXRpb24gd2UgbmVlZCB0byBhZGQgdGhlIGF1dGhlbnRpY2F0aW9uIHRpY2tldFxuICAgICAgICAvLyBJdCBpcyBjb250YWluZWQgaW4gdXJsUGFyYW1zXG4gICAgICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgICAgIGNvbnN0IHJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9maWx0ZXJpbmcvXCIgKyBvd25lck5hbWUgKyBcIj9cIiArIHVybFBhcmFtcywge1xuICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KGZpbHRlclJlcXVlc3QpLFxuICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCByZXN1bHQgPSAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIEZpbHRlcmluZ0Fuc3dlclxuICAgICAgICBpZiAoIXJlc3VsdC5zdWNjZXNzKSB7IGFsZXJ0KHJlc3VsdC5mYWlsdXJlTWVzc2FnZSkgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGNsZWFyaW5nTWVzc2FnZXMoKVxuICAgICAgICAgICAgZm9yICh2YXIgZmlsdF9tZXNzYWdlIG9mIHJlc3VsdC5hbGxNZXNzYWdlcykge1xuICAgICAgICAgICAgICAgIGlmIChmaWx0X21lc3NhZ2UuZGVsZXRlZCkge1xuICAgICAgICAgICAgICAgICAgICBhZGRpbmdGaWx0ZXJlZE1lc3NhZ2UoYEluZGV4OiAke2ZpbHRfbWVzc2FnZS5pbmRleH0gRGVsZXRlZCBieTogJHtmaWx0X21lc3NhZ2UuZGVsZXRlcn0gPHN0cmlrZT4gRnJvbTogJHtmaWx0X21lc3NhZ2UubWVzc2FnZS5zZW5kZXJ9IFRvOiAke2ZpbHRfbWVzc2FnZS5tZXNzYWdlLnJlY2VpdmVyfSBDb250ZW50OiAke2ZpbHRfbWVzc2FnZS5tZXNzYWdlLmNvbnRlbnR9IDwvc3RyaWtlPmApXG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgYWRkaW5nRmlsdGVyZWRNZXNzYWdlKGBJbmRleDogJHtmaWx0X21lc3NhZ2UuaW5kZXh9IEZyb206ICR7ZmlsdF9tZXNzYWdlLm1lc3NhZ2Uuc2VuZGVyfSBUbzogJHtmaWx0X21lc3NhZ2UubWVzc2FnZS5yZWNlaXZlcn0gQ29udGVudDogJHtmaWx0X21lc3NhZ2UubWVzc2FnZS5jb250ZW50fWApXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBFcnJvcikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coJ2Vycm9yIG1lc3NhZ2U6ICcsIGVycm9yLm1lc3NhZ2UpO1xuICAgICAgICAgICAgcmV0dXJuIGVycm9yLm1lc3NhZ2U7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygndW5leHBlY3RlZCBlcnJvcjogJywgZXJyb3IpO1xuICAgICAgICAgICAgcmV0dXJuICdBbiB1bmV4cGVjdGVkIGVycm9yIG9jY3VycmVkJztcbiAgICAgICAgfVxuICAgIH1cbn1cblxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQTBDQSxlQUFzQiwrQkFBK0IsWUFBd0M7QUFDekYsTUFBSTtBQUNBLFVBQU0saUJBQThCLDBCQUEwQixVQUFVO0FBQ3hFLFVBQU0sTUFBaUIsTUFBTSxPQUFPLE9BQU8sT0FBTztBQUFBLE1BQzlDO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxRQUNJLE1BQU07QUFBQSxRQUNOLE1BQU07QUFBQSxNQUNWO0FBQUEsTUFDQTtBQUFBLE1BQ0EsQ0FBQyxTQUFTO0FBQUEsSUFDZDtBQUNBLFdBQU87QUFBQSxFQUNYLFNBQVMsR0FBRztBQUNSLFFBQUksYUFBYSxjQUFjO0FBQUUsY0FBUSxJQUFJLDJEQUEyRDtBQUFBLElBQUUsV0FDakcsYUFBYSxvQkFBb0I7QUFBRSxjQUFRLElBQUksMkRBQTJEO0FBQUEsSUFBRSxPQUNoSDtBQUFFLGNBQVEsSUFBSSxDQUFDO0FBQUEsSUFBRTtBQUN0QixVQUFNO0FBQUEsRUFDVjtBQUNKO0FBTUEsZUFBc0IsOEJBQThCLFlBQXdDO0FBQ3hGLE1BQUk7QUFDQSxVQUFNLGlCQUE4QiwwQkFBMEIsVUFBVTtBQUN4RSxVQUFNLE1BQWlCLE1BQU0sT0FBTyxPQUFPLE9BQU87QUFBQSxNQUM5QztBQUFBLE1BQ0E7QUFBQSxNQUNBO0FBQUEsUUFDSSxNQUFNO0FBQUEsUUFDTixNQUFNO0FBQUEsTUFDVjtBQUFBLE1BQ0E7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RztBQUNSLFFBQUksYUFBYSxPQUFPO0FBQ3BCLGNBQVEsSUFBSSxFQUFFLE9BQU87QUFBQSxJQUN6QixPQUFPO0FBQ0gsY0FBUSxJQUFJLENBQUM7QUFBQSxJQUNqQjtBQUFBLEVBQ0o7QUFDSjtBQUVBLGFBQWEsVUFBVSxpQkFBa0I7QUFDckMsTUFBSTtBQUNBLFVBQU0sV0FBVyxLQUFLO0FBQ3RCLFVBQU0sU0FBUyxHQUFHO0FBQ2xCLFVBQU0sV0FBVyxZQUFZO0FBQzdCLFVBQU0sZ0JBQ0YsSUFBSSxjQUFjLFVBQVUsUUFBUSxRQUFRO0FBR2hELFVBQU0sWUFBWSxJQUFJLGdCQUFnQixPQUFPLFNBQVMsTUFBTTtBQUM1RCxVQUFNLFVBQVUsTUFBTSxNQUFNLGdCQUFnQixZQUFZLE1BQU0sV0FBVztBQUFBLE1BQ3JFLFFBQVE7QUFBQSxNQUNSLE1BQU0sS0FBSyxVQUFVLGFBQWE7QUFBQSxNQUNsQyxTQUFTO0FBQUEsUUFDTCxnQkFBZ0I7QUFBQSxNQUNwQjtBQUFBLElBQ0osQ0FBQztBQUNELFFBQUksQ0FBQyxRQUFRLElBQUk7QUFDYixZQUFNLElBQUksTUFBTSxrQkFBa0IsUUFBUSxNQUFNLEVBQUU7QUFBQSxJQUN0RDtBQUNBLFVBQU0sU0FBVSxNQUFNLFFBQVEsS0FBSztBQUNuQyxRQUFJLENBQUMsT0FBTyxTQUFTO0FBQUUsWUFBTSxPQUFPLGNBQWM7QUFBQSxJQUFFLE9BQy9DO0FBQ0QsdUJBQWlCO0FBQ2pCLGVBQVMsZ0JBQWdCLE9BQU8sYUFBYTtBQUN6QyxZQUFJLGFBQWEsU0FBUztBQUN0QixnQ0FBc0IsVUFBVSxhQUFhLEtBQUssZ0JBQWdCLGFBQWEsT0FBTyxtQkFBbUIsYUFBYSxRQUFRLE1BQU0sUUFBUSxhQUFhLFFBQVEsUUFBUSxhQUFhLGFBQWEsUUFBUSxPQUFPLFlBQVk7QUFBQSxRQUNsTyxPQUFPO0FBQ0gsZ0NBQXNCLFVBQVUsYUFBYSxLQUFLLFVBQVUsYUFBYSxRQUFRLE1BQU0sUUFBUSxhQUFhLFFBQVEsUUFBUSxhQUFhLGFBQWEsUUFBUSxPQUFPLEVBQUU7QUFBQSxRQUMzSztBQUFBLE1BQ0o7QUFBQSxJQUNKO0FBQUEsRUFDSixTQUNPLE9BQU87QUFDVixRQUFJLGlCQUFpQixPQUFPO0FBQ3hCLGNBQVEsSUFBSSxtQkFBbUIsTUFBTSxPQUFPO0FBQzVDLGFBQU8sTUFBTTtBQUFBLElBQ2pCLE9BQU87QUFDSCxjQUFRLElBQUksc0JBQXNCLEtBQUs7QUFDdkMsYUFBTztBQUFBLElBQ1g7QUFBQSxFQUNKO0FBQ0o7IiwKICAibmFtZXMiOiBbImZyb20iLCAidG8iXQp9Cg==
