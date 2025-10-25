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
async function encryptWithPublicKey(publicKey, message3) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message3);
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
async function signWithPrivateKey(privateKey, message3) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message3);
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
async function decryptWithPrivateKey(privateKey, message3) {
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64StringToArrayBuffer(message3)
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
async function verifySignatureWithPublicKey(publicKey, messageInClear2, signedMessage) {
  try {
    const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage);
    const messageInClearToArrayBuffer = textToArrayBuffer(messageInClear2);
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
async function encryptWithSymmetricKey(key, message3) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message3);
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
async function decryptWithSymmetricKey(key, message3, initVector) {
  const decodedInitVector = base64StringToArrayBuffer(initVector);
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodedInitVector },
      key,
      base64StringToArrayBuffer(message3)
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
  constructor(from, to, indexmin) {
    this.from = from;
    this.to = to;
    this.indexmin = indexmin;
  }
};
var FilteredMessage = class {
  constructor(message3, index, deleted, deleter) {
    this.message = message3;
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
  constructor(sender, receiver2, content) {
    this.sender = sender;
    this.receiver = receiver2;
    this.content = content;
  }
};
var DeletingRequest = class {
  constructor(indexToDelete) {
    this.indexToDelete = indexToDelete;
  }
};
var DeletingAnswer = class {
  constructor(success, message3) {
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

// src/messengerNaive.ts
if (!window.isSecureContext) alert("Not secure context!");
var lastIndexInHistory = 0;
var userButtonLabel = document.getElementById("user-name");
var sendButton = document.getElementById("send-button");
var receiver = document.getElementById("receiver");
var message2 = document.getElementById("message");
var received_messages = document.getElementById("exchanged-messages");
function clearingMessages() {
  received_messages.textContent = "";
}
function stringToHTML(str) {
  var div_elt = document.createElement("div");
  div_elt.innerHTML = str;
  return div_elt;
}
function addingReceivedMessage(message3) {
  received_messages.append(stringToHTML("<p></p><p></p>" + message3));
}
var globalUserName = "";
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
  globalUserName = await fetchCasName();
  userButtonLabel.textContent = globalUserName;
}
setCasName();
function getOwnerName() {
  const path = window.location.pathname;
  const name = path.split("/", 2)[1];
  return name;
}
var ownerName = getOwnerName();
async function fetchKey(user2, publicKey, encryption) {
  const keyRequestMessage = new KeyRequest(user2, publicKey, encryption);
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
    if (publicKey && encryption) return await stringToPublicKeyForEncryption(keyResult.key);
    else if (!publicKey && encryption) return await stringToPrivateKeyForEncryption(keyResult.key);
    else if (publicKey && !encryption) return await stringToPublicKeyForSignature(keyResult.key);
    else if (!publicKey && !encryption) return await stringToPrivateKeyForSignature(keyResult.key);
  }
}
async function sendMessage(agentName, receiverName, messageContent2) {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent2);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/sendingMessage/" + ownerName + "?" + urlParams, {
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
      console.log("error message: ", error.message);
      return new SendResult(false, error.message);
    } else {
      console.log("unexpected error: ", error);
      return new SendResult(false, "An unexpected error occurred");
    }
  }
}
message2.addEventListener("keyup", function(event) {
  if (event.key === "Enter") {
    sendButton.click();
  }
});
sendButton.onclick = async function() {
  let agentName = globalUserName;
  let receiverName = receiver.value;
  let contentToEncrypt = JSON.stringify([agentName, message2.value]);
  try {
    const kb = await fetchKey(receiverName, true, true);
    const encryptedMessage = await encryptWithPublicKey(kb, contentToEncrypt);
    const sendResult = await sendMessage(agentName, receiverName, encryptedMessage);
    if (!sendResult.success) console.log(sendResult.errorMessage);
    else {
      console.log("Successfully sent the message!");
      const textToAdd = `<font color="blue"> ${agentName} -> ${receiverName} : (${readableTime()}) ${message2.value} </font>`;
      addingReceivedMessage(textToAdd);
    }
  } catch (e) {
    if (e instanceof Error) {
      console.log("error message: ", e.message);
    } else {
      console.log("unexpected error: ", e);
    }
  }
};
function readableTime() {
  const now = /* @__PURE__ */ new Date();
  const hours = now.getHours().toString();
  const minutes = now.getMinutes().toString();
  const seconds = now.getSeconds().toString();
  return `${hours.length === 1 ? "0" + hours : hours}:${minutes.length === 1 ? "0" + minutes : minutes}:${seconds.length === 1 ? "0" + seconds : seconds}`;
}
async function analyseMessage(message) {
  const user = globalUserName;
  try {
    const messageSender = message.sender;
    const messageContent = message.content;
    if (message.receiver !== user) {
      return [false, "", ""];
    } else {
      try {
        const privkey = await fetchKey(user, false, true);
        const messageInClearString = await decryptWithPrivateKey(privkey, messageContent);
        const messageArrayInClear = JSON.parse(messageInClearString);
        const messageSenderInMessage = messageArrayInClear[0];
        const messageInClear = messageArrayInClear[1];
        if (messageSenderInMessage == messageSender) {
          return [true, messageSender, eval("`(${readableTime()}) " + messageInClear + "`")];
        } else {
          console.log("Real message sender and message sender name in the message do not coincide");
        }
      } catch (e) {
        console.log("analyseMessage: decryption failed because of " + e);
        return [false, "", ""];
      }
    }
  } catch (e) {
    console.log("analyseMessage: decryption failed because of " + e);
    return [false, "", ""];
  }
}
function actionOnMessageOne(fromA, messageContent2) {
  const user2 = globalUserName;
  const textToAdd = `${fromA} -> ${user2} : ${messageContent2} `;
  addingReceivedMessage(textToAdd);
}
async function refresh() {
  try {
    const user2 = globalUserName;
    const historyRequest = new HistoryRequest(user2, lastIndexInHistory);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch(
      "/history/" + ownerName + "?" + urlParams,
      {
        method: "POST",
        body: JSON.stringify(historyRequest),
        headers: {
          "Content-type": "application/json; charset=UTF-8"
        }
      }
    );
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status} `);
    }
    const result = await request.json();
    if (!result.success) {
      alert(result.failureMessage);
    } else {
      lastIndexInHistory = result.index;
      if (result.allMessages.length != 0) {
        for (var m of result.allMessages) {
          let [b, sender, msgContent] = await analyseMessage(m);
          if (b) actionOnMessageOne(sender, msgContent);
          else console.log("Msg " + m + " cannot be exploited by " + user2);
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
}
var intervalRefresh = setInterval(refresh, 2e3);
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvc2VydmVyTWVzc2FnZXMudHMiLCAiLi4vc3JjL21lc3Nlbmdlck5haXZlLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBTb3VyY2U6IGh0dHBzOi8vZ2lzdC5naXRodWIuY29tL2dyb3VuZHJhY2UvYjUxNDEwNjJiNDdkZDk2YTVjMjFjOTM4MzlkNGI5NTQgKi9cblxuLyogQXZhaWxhYmxlIGZ1bmN0aW9uczpcblxuICAgICMgS2V5L25vbmNlIGdlbmVyYXRpb246XG4gICAgZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT5cbiAgICBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBnZW5lcmF0ZU5vbmNlKCk6IHN0cmluZ1xuXG4gICAgIyBBc3N5bWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb24vU2lnbmF0dXJlL1NpZ25hdHVyZSB2ZXJpZmljYXRpb25cbiAgICBlbmNyeXB0V2l0aFB1YmxpY0tleShwa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShza2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj5cblxuICAgICMgU3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb25cbiAgICBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT5cbiAgICBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSW1wb3J0aW5nIGtleXMgZnJvbSBzdHJpbmdcbiAgICBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoc2tleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cblxuICAgICMgRXhwb3J0aW5nIGtleXMgdG8gc3RyaW5nXG4gICAgcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBwcml2YXRlS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPlxuXG4gICAgIyBIYXNoaW5nXG4gICAgaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiovXG5cbi8vIExpYkNyeXB0by0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIl1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShwa2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIocGtleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInNwa2lcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1widmVyaWZ5XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKVxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJwa2NzOFwiID8/IGZvcm1hdCBmb3IgaW1wb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBLU9BRVBcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHJpdmF0ZSBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSlcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wic2lnblwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwdWJsaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwic3BraVwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEdlbmVyYXRlcyBhIHBhaXIgb2YgcHVibGljIGFuZCBwcml2YXRlIFJTQSBrZXlzIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yRW5jcnlwdGlvbigpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIFtrZXlwYWlyLnB1YmxpY0tleSwga2V5cGFpci5wcml2YXRlS2V5XVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3Igc2lnbmluZy92ZXJpZnlpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUFzc3ltZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+IHtcbiAgICBjb25zdCBrZXlwYWlyOiBDcnlwdG9LZXlQYWlyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IDIwNDgsXG4gICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzEsIDAsIDFdKSxcbiAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJzaWduXCIsIFwidmVyaWZ5XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcmFuZG9tIG5vbmNlICovXG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmcge1xuICAgIGNvbnN0IG5vbmNlQXJyYXkgPSBuZXcgVWludDMyQXJyYXkoMSlcbiAgICBzZWxmLmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobm9uY2VBcnJheSlcbiAgICByZXR1cm4gbm9uY2VBcnJheVswXS50b1N0cmluZygpXG59XG5cbi8qIEVuY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKiBTaWduIGEgbWVzc2FnZSB3aXRoIGEgcHJpdmF0ZSBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzaWduV2l0aFByaXZhdGVLZXkocHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3Qgc2lnbmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLnNpZ24oXG4gICAgICAgICAgICBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICBwcml2YXRlS2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhzaWduZWRNZXNzYWdlQUIpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhlKTsgY29uc29sZS5sb2coXCJTaWduYXR1cmUgZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJQcml2YXRlIGtleSBvciBtZXNzYWdlIHRvIHNpZ24gaXMgaWxsLWZvcm1lZFwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLyogRGVjcnlwdHMgYSBtZXNzYWdlIHdpdGggYSBwcml2YXRlIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgZGVjcnl0cGVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0XG4gICAgICAgICAgICB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kZWNyeXB0KFxuICAgICAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICAgICAgcHJpdmF0ZUtleSxcbiAgICAgICAgICAgICAgICBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvVGV4dChkZWNyeXRwZWRNZXNzYWdlQUIpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJJbnZhbGlkIGtleSwgbWVzc2FnZSBvciBhbGdvcml0aG0gZm9yIGRlY3J5cHRpb25cIilcbiAgICAgICAgfSBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlByaXZhdGUga2V5IG9yIG1lc3NhZ2UgdG8gZGVjcnlwdCBpcyBpbGwtZm9ybWVkXCIpXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLyogVmVyaWZpY2F0aW9uIG9mIGEgc2lnbmF0dXJlIG9uIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHNpZ25lZFRvQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHNpZ25lZE1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IG1lc3NhZ2VJbkNsZWFyVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2VJbkNsZWFyKVxuICAgICAgICBjb25zdCB2ZXJpZmllZDogYm9vbGVhbiA9IGF3YWl0XG4gICAgICAgICAgICB3aW5kb3cuY3J5cHRvLnN1YnRsZS52ZXJpZnkoXG4gICAgICAgICAgICAgICAgXCJSU0FTU0EtUEtDUzEtdjFfNVwiLFxuICAgICAgICAgICAgICAgIHB1YmxpY0tleSxcbiAgICAgICAgICAgICAgICBzaWduZWRUb0FycmF5QnVmZmVyLFxuICAgICAgICAgICAgICAgIG1lc3NhZ2VJbkNsZWFyVG9BcnJheUJ1ZmZlcilcbiAgICAgICAgcmV0dXJuIHZlcmlmaWVkXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJJbnZhbGlkIGtleSwgbWVzc2FnZSBvciBhbGdvcml0aG0gZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb25cIilcbiAgICAgICAgfSBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3Igc2lnbmVkIG1lc3NhZ2UgdG8gdmVyaWZ5IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBHZW5lcmF0ZXMgYSBzeW1tZXRyaWMgQUVTLUdDTSBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVN5bWV0cmljS2V5KCk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShcbiAgICAgICAge1xuICAgICAgICAgICAgbmFtZTogXCJBRVMtR0NNXCIsXG4gICAgICAgICAgICBsZW5ndGg6IDI1NixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIGtleVxufVxuXG4vKiBhIHN5bW1ldHJpYyBBRVMga2V5IGludG8gYSBzdHJpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwicmF3XCIsIGtleSlcbiAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhleHBvcnRlZEtleSlcbn1cblxuLyogSW1wb3J0cyB0aGUgZ2l2ZW4ga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgQUVTIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN0cmluZ1RvU3ltbWV0cmljS2V5KHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicmF3XCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIFwiQUVTLUdDTVwiLFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHN5bW1ldHJpYyBrZXkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgc3ltbWV0cmljIGtleSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLy8gV2hlbiBjeXBoZXJpbmcgYSBtZXNzYWdlIHdpdGggYSBrZXkgaW4gQUVTLCB3ZSBvYnRhaW4gYSBjeXBoZXJlZCBtZXNzYWdlIGFuZCBhbiBcImluaXRpYWxpc2F0aW9uIHZlY3RvclwiLlxuLy8gSW4gdGhpcyBpbXBsZW1lbnRhdGlvbiwgdGhlIG91dHB1dCBpcyBhIHR3byBlbGVtZW50cyBhcnJheSB0IHN1Y2ggdGhhdCB0WzBdIGlzIHRoZSBjeXBoZXJlZCBtZXNzYWdlXG4vLyBhbmQgdFsxXSBpcyB0aGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yLiBUbyBzaW1wbGlmeSwgdGhlIGluaXRpYWxpc2F0aW9uIHZlY3RvciBpcyByZXByZXNlbnRlZCBieSBhIHN0cmluZy5cbi8vIFRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3JlIGlzIHVzZWQgZm9yIHByb3RlY3RpbmcgdGhlIGVuY3J5cHRpb24sIGkuZSwgMiBlbmNyeXB0aW9ucyBvZiB0aGUgc2FtZSBtZXNzYWdlIFxuLy8gd2l0aCB0aGUgc2FtZSBrZXkgd2lsbCBuZXZlciByZXN1bHQgaW50byB0aGUgc2FtZSBlbmNyeXB0ZWQgbWVzc2FnZS5cbi8vIFxuLy8gTm90ZSB0aGF0IGZvciBkZWN5cGhlcmluZywgdGhlICoqc2FtZSoqIGluaXRpYWxpc2F0aW9uIHZlY3RvciB3aWxsIGJlIG5lZWRlZC5cbi8vIFRoaXMgdmVjdG9yIGNhbiBzYWZlbHkgYmUgdHJhbnNmZXJyZWQgaW4gY2xlYXIgd2l0aCB0aGUgZW5jcnlwdGVkIG1lc3NhZ2UuXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgaXYgPSB3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSgxMikpO1xuICAgICAgICBjb25zdCBpdlRleHQgPSBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGl2KVxuICAgICAgICBjb25zdCBjeXBoZXJlZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5lbmNyeXB0KFxuICAgICAgICAgICAgeyBuYW1lOiBcIkFFUy1HQ01cIiwgaXYgfSxcbiAgICAgICAgICAgIGtleSxcbiAgICAgICAgICAgIG1lc3NhZ2VUb0FycmF5QnVmZmVyXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIFthcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKSwgaXZUZXh0XVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN5bW1ldHJpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vLyBGb3IgZGVjeXBoZXJpbmcsIHdlIG5lZWQgdGhlIGtleSwgdGhlIGN5cGhlcmVkIG1lc3NhZ2UgYW5kIHRoZSBpbml0aWFsaXphdGlvbiB2ZWN0b3IuIFNlZSBhYm92ZSB0aGUgXG4vLyBjb21tZW50cyBmb3IgdGhlIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5IGZ1bmN0aW9uXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVjcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZywgaW5pdFZlY3Rvcjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBkZWNvZGVkSW5pdFZlY3RvcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKGluaXRWZWN0b3IpXG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgZGVjcnl0cGVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0XG4gICAgICAgICAgICB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kZWNyeXB0KFxuICAgICAgICAgICAgICAgIHsgbmFtZTogXCJBRVMtR0NNXCIsIGl2OiBkZWNvZGVkSW5pdFZlY3RvciB9LFxuICAgICAgICAgICAgICAgIGtleSxcbiAgICAgICAgICAgICAgICBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvVGV4dChkZWNyeXRwZWRNZXNzYWdlQUIpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJJbnZhbGlkIGtleSwgbWVzc2FnZSBvciBhbGdvcml0aG0gZm9yIGRlY3J5cHRpb25cIilcbiAgICAgICAgfSBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlN5bW1ldHJpYyBrZXkgb3IgbWVzc2FnZSB0byBkZWNyeXB0IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLy8gU0hBLTI1NiBIYXNoIGZyb20gYSB0ZXh0XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHRleHQyYXJyYXlCdWYgPSB0ZXh0VG9BcnJheUJ1ZmZlcih0ZXh0KVxuICAgIGNvbnN0IGhhc2hlZEFycmF5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZGlnZXN0KFwiU0hBLTI1NlwiLCB0ZXh0MmFycmF5QnVmKVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGhhc2hlZEFycmF5KVxufVxuXG5jbGFzcyBLZXlTdHJpbmdDb3JydXB0ZWQgZXh0ZW5kcyBFcnJvciB7IH1cblxuLy8gQXJyYXlCdWZmZXIgdG8gYSBCYXNlNjQgc3RyaW5nXG5mdW5jdGlvbiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gICAgdmFyIGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKVxuICAgIHZhciBieXRlU3RyaW5nID0gJydcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVBcnJheS5ieXRlTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnl0ZVN0cmluZyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGVBcnJheVtpXSlcbiAgICB9XG4gICAgcmV0dXJuIGJ0b2EoYnl0ZVN0cmluZylcbn1cblxuLy8gQmFzZTY0IHN0cmluZyB0byBhbiBhcnJheUJ1ZmZlclxuZnVuY3Rpb24gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihiNjRzdHI6IHN0cmluZyk6IEFycmF5QnVmZmVyIHtcbiAgICB0cnkge1xuICAgICAgICB2YXIgYnl0ZVN0ciA9IGF0b2IoYjY0c3RyKVxuICAgICAgICB2YXIgYnl0ZXMgPSBuZXcgVWludDhBcnJheShieXRlU3RyLmxlbmd0aClcbiAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlU3RyLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBieXRlc1tpXSA9IGJ5dGVTdHIuY2hhckNvZGVBdChpKVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBieXRlcy5idWZmZXJcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBTdHJpbmcgc3RhcnRpbmcgYnkgJyR7YjY0c3RyLnN1YnN0cmluZygwLCAxMCl9JyBjYW5ub3QgYmUgY29udmVydGVkIHRvIGEgdmFsaWQga2V5IG9yIG1lc3NhZ2VgKVxuICAgICAgICB0aHJvdyBuZXcgS2V5U3RyaW5nQ29ycnVwdGVkXG4gICAgfVxufVxuXG4vLyBTdHJpbmcgdG8gYXJyYXkgYnVmZmVyXG5mdW5jdGlvbiB0ZXh0VG9BcnJheUJ1ZmZlcihzdHI6IHN0cmluZyk6IEFycmF5QnVmZmVyIHtcbiAgICB2YXIgYnVmID0gZW5jb2RlVVJJQ29tcG9uZW50KHN0cikgLy8gMiBieXRlcyBmb3IgZWFjaCBjaGFyXG4gICAgdmFyIGJ1ZlZpZXcgPSBuZXcgVWludDhBcnJheShidWYubGVuZ3RoKVxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnVmLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGJ1ZlZpZXdbaV0gPSBidWYuY2hhckNvZGVBdChpKVxuICAgIH1cbiAgICByZXR1cm4gYnVmVmlld1xufVxuXG4vLyBBcnJheSBidWZmZXJzIHRvIHN0cmluZ1xuZnVuY3Rpb24gYXJyYXlCdWZmZXJUb1RleHQoYXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgICB2YXIgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpXG4gICAgdmFyIHN0ciA9ICcnXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlQXJyYXkuYnl0ZUxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHN0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGJ5dGVBcnJheVtpXSlcbiAgICB9XG4gICAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudChzdHIpXG59XG5cbiIsICIvLyBBbGwgbWVzc2FnZSB0eXBlcyBiZXR3ZWVuIHRoZSBhcHBsaWNhdGlvbiBhbmQgdGhlIHNlcnZlclxuLy8gTWVzc2FnZSBmb3IgdXNlciBuYW1lXG5leHBvcnQgY2xhc3MgQ2FzVXNlck5hbWUge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyB1c2VybmFtZTogc3RyaW5nKSB7IH1cbn1cblxuXG4vLyBNZXNzYWdlIGZvciByZXF1aXJpbmcgaGlzdG9yeVxuZXhwb3J0IGNsYXNzIEhpc3RvcnlSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgYWdlbnROYW1lOiBzdHJpbmcsIHB1YmxpYyBpbmRleDogbnVtYmVyKSB7IH1cbn1cblxuLy8gUmVzdWx0IG9mIGhpc3RvcnkgcmVxdWVzdFxuZXhwb3J0IGNsYXNzIEhpc3RvcnlBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBwdWJsaWMgZmFpbHVyZU1lc3NhZ2U6IHN0cmluZyxcbiAgICAgICAgcHVibGljIGluZGV4OiBudW1iZXIsXG4gICAgICAgIHB1YmxpYyBhbGxNZXNzYWdlczogRXh0TWVzc2FnZVtdKSB7IH1cbn1cblxuLy8gRmlsdGVyaW5nIG9mIG1lc3NhZ2VzXG5leHBvcnQgY2xhc3MgRmlsdGVyUmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIGZyb206IHN0cmluZywgcHVibGljIHRvOiBzdHJpbmcsIHB1YmxpYyBpbmRleG1pbjogc3RyaW5nKSB7IH1cbn1cblxuZXhwb3J0IGNsYXNzIEZpbHRlcmVkTWVzc2FnZSB7XG4gICAgY29uc3RydWN0b3IocHVibGljIG1lc3NhZ2U6IEV4dE1lc3NhZ2UsXG4gICAgICAgIHB1YmxpYyBpbmRleDogbnVtYmVyLFxuICAgICAgICBwdWJsaWMgZGVsZXRlZDogYm9vbGVhbixcbiAgICAgICAgcHVibGljIGRlbGV0ZXI6IHN0cmluZykgeyB9XG59XG5cbi8vIFJlc3VsdCBvZiBmaWx0ZXJpbmcgcmVxdWVzdFxuZXhwb3J0IGNsYXNzIEZpbHRlcmluZ0Fuc3dlciB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sXG4gICAgICAgIHB1YmxpYyBmYWlsdXJlTWVzc2FnZTogc3RyaW5nLFxuICAgICAgICBwdWJsaWMgYWxsTWVzc2FnZXM6IEZpbHRlcmVkTWVzc2FnZVtdKSB7IH1cbn1cblxuLy8gU2VuZGluZyBhIG1lc3NhZ2UgUmVzdWx0IGZvcm1hdFxuZXhwb3J0IGNsYXNzIFNlbmRSZXN1bHQge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLCBwdWJsaWMgZXJyb3JNZXNzYWdlOiBzdHJpbmcpIHsgfVxufVxuXG4vLyBTZW5kaW5nIG1lc3NhZ2VzXG4vLyBUaGUgbWVzc2FnZSBmb3JtYXRcbmV4cG9ydCBjbGFzcyBFeHRNZXNzYWdlIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc2VuZGVyOiBzdHJpbmcsIHB1YmxpYyByZWNlaXZlcjogc3RyaW5nLCBwdWJsaWMgY29udGVudDogc3RyaW5nKSB7IH1cbn1cblxuZXhwb3J0IGNsYXNzIERlbGV0aW5nUmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IoXG4gICAgICAgIHB1YmxpYyBpbmRleFRvRGVsZXRlOiBzdHJpbmcpIHsgfVxufVxuXG5leHBvcnQgY2xhc3MgRGVsZXRpbmdBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBtZXNzYWdlOiBzdHJpbmcpIHsgfVxufVxuXG4vLyBSZXF1ZXN0aW5nIGtleXNcbmV4cG9ydCBjbGFzcyBLZXlSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgb3duZXJPZlRoZUtleTogc3RyaW5nLCBwdWJsaWMgcHVibGljS2V5OiBib29sZWFuLCBwdWJsaWMgZW5jcnlwdGlvbjogYm9vbGVhbikgeyB9XG59XG5cbmV4cG9ydCBjbGFzcyBLZXlSZXN1bHQge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLCBwdWJsaWMga2V5OiBzdHJpbmcsIHB1YmxpYyBlcnJvck1lc3NhZ2U6IHN0cmluZykgeyB9XG59IiwgIi8qIFxuaHR0cDovL2xvY2FsaG9zdDo4MDgwL21lc3Nlbmdlck5haXZlMi5odG1sXG5Vc2FnZTogb3V2cmlyIDIgb25nbGV0cyBzdXIgbG9jYWxob3N0OjgwODAvXG4qL1xuXG5pbXBvcnQge1xuICAgIGVuY3J5cHRXaXRoUHVibGljS2V5LCBkZWNyeXB0V2l0aFByaXZhdGVLZXksIHN0cmluZ1RvUHJpdmF0ZUtleUZvckVuY3J5cHRpb24sIHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbixcbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUsXG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUsIHByaXZhdGVLZXlUb1N0cmluZ1xufSBmcm9tICcuL2xpYkNyeXB0bydcblxuaW1wb3J0IHtcbiAgICBIaXN0b3J5QW5zd2VyLCBIaXN0b3J5UmVxdWVzdCwgS2V5UmVxdWVzdCwgS2V5UmVzdWx0LCBDYXNVc2VyTmFtZSwgRXh0TWVzc2FnZSwgU2VuZFJlc3VsdCxcblxufSBmcm9tICcuL3NlcnZlck1lc3NhZ2VzJ1xuXG4vLyBUbyBkZXRlY3QgaWYgd2UgY2FuIHVzZSB3aW5kb3cuY3J5cHRvLnN1YnRsZVxuaWYgKCF3aW5kb3cuaXNTZWN1cmVDb250ZXh0KSBhbGVydChcIk5vdCBzZWN1cmUgY29udGV4dCFcIilcblxuLy9JbmRleCBvZiB0aGUgbGFzdCByZWFkIG1lc3NhZ2VcbmxldCBsYXN0SW5kZXhJbkhpc3RvcnkgPSAwXG5cbmNvbnN0IHVzZXJCdXR0b25MYWJlbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwidXNlci1uYW1lXCIpIGFzIEhUTUxMYWJlbEVsZW1lbnRcblxuY29uc3Qgc2VuZEJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwic2VuZC1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcblxuY29uc3QgcmVjZWl2ZXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInJlY2VpdmVyXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IG1lc3NhZ2UgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcIm1lc3NhZ2VcIikgYXMgSFRNTElucHV0RWxlbWVudFxuY29uc3QgcmVjZWl2ZWRfbWVzc2FnZXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImV4Y2hhbmdlZC1tZXNzYWdlc1wiKSBhcyBIVE1MTGFiZWxFbGVtZW50XG5cbmZ1bmN0aW9uIGNsZWFyaW5nTWVzc2FnZXMoKSB7XG4gICAgcmVjZWl2ZWRfbWVzc2FnZXMudGV4dENvbnRlbnQgPSBcIlwiXG59XG5cbmZ1bmN0aW9uIHN0cmluZ1RvSFRNTChzdHI6IHN0cmluZyk6IEhUTUxEaXZFbGVtZW50IHtcbiAgICB2YXIgZGl2X2VsdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpXG4gICAgZGl2X2VsdC5pbm5lckhUTUwgPSBzdHJcbiAgICByZXR1cm4gZGl2X2VsdFxufVxuXG5mdW5jdGlvbiBhZGRpbmdSZWNlaXZlZE1lc3NhZ2UobWVzc2FnZTogc3RyaW5nKSB7XG4gICAgcmVjZWl2ZWRfbWVzc2FnZXMuYXBwZW5kKHN0cmluZ1RvSFRNTCgnPHA+PC9wPjxwPjwvcD4nICsgbWVzc2FnZSkpXG59XG5cbi8qIE5hbWUgb2YgdGhlIHVzZXIgb2YgdGhlIGFwcGxpY2F0aW9uLi4uIGNhbiBiZSBBbGljZS9Cb2IgZm9yIGF0dGFja2luZyBwdXJwb3NlcyAqL1xubGV0IGdsb2JhbFVzZXJOYW1lID0gXCJcIlxuXG5hc3luYyBmdW5jdGlvbiBmZXRjaENhc05hbWUoKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCB1cmxQYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpO1xuICAgIGNvbnN0IG5hbWVyZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvZ2V0dXNlcj9cIiArIHVybFBhcmFtcywge1xuICAgICAgICBtZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgIH1cbiAgICB9KTtcbiAgICBpZiAoIW5hbWVyZXF1ZXN0Lm9rKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtuYW1lcmVxdWVzdC5zdGF0dXN9YCk7XG4gICAgfVxuICAgIGNvbnN0IG5hbWVSZXN1bHQgPSAoYXdhaXQgbmFtZXJlcXVlc3QuanNvbigpKSBhcyBDYXNVc2VyTmFtZTtcbiAgICByZXR1cm4gbmFtZVJlc3VsdC51c2VybmFtZVxufVxuXG5hc3luYyBmdW5jdGlvbiBzZXRDYXNOYW1lKCkge1xuICAgIGdsb2JhbFVzZXJOYW1lID0gYXdhaXQgZmV0Y2hDYXNOYW1lKClcbiAgICAvLyBXZSByZXBsYWNlIHRoZSBuYW1lIG9mIHRoZSB1c2VyIG9mIHRoZSBhcHBsaWNhdGlvbiBhcyB0aGUgZGVmYXVsdCBuYW1lXG4gICAgLy8gSW4gdGhlIHdpbmRvd1xuICAgIHVzZXJCdXR0b25MYWJlbC50ZXh0Q29udGVudCA9IGdsb2JhbFVzZXJOYW1lXG59XG5cbnNldENhc05hbWUoKVxuXG4vKiBOYW1lIG9mIHRoZSBvd25lci9kZXZlbG9wcGVyIG9mIHRoZSBhcHBsaWNhdGlvbiwgaS5lLCB0aGUgbmFtZSBvZiB0aGUgZm9sZGVyIFxuICAgd2hlcmUgdGhlIHdlYiBwYWdlIG9mIHRoZSBhcHBsaWNhdGlvbiBpcyBzdG9yZWQuIEUuZywgZm9yIHRlYWNoZXJzJyBhcHBsaWNhdGlvblxuICAgdGhpcyBuYW1lIGlzIFwiZW5zXCIgKi9cblxuZnVuY3Rpb24gZ2V0T3duZXJOYW1lKCk6IHN0cmluZyB7XG4gICAgY29uc3QgcGF0aCA9IHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZVxuICAgIGNvbnN0IG5hbWUgPSBwYXRoLnNwbGl0KFwiL1wiLCAyKVsxXVxuICAgIHJldHVybiBuYW1lXG59XG5cbmxldCBvd25lck5hbWUgPSBnZXRPd25lck5hbWUoKVxuXG5hc3luYyBmdW5jdGlvbiBmZXRjaEtleSh1c2VyOiBzdHJpbmcsIHB1YmxpY0tleTogYm9vbGVhbiwgZW5jcnlwdGlvbjogYm9vbGVhbik6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgLy8gR2V0dGluZyB0aGUgcHVibGljL3ByaXZhdGUga2V5IG9mIHVzZXIuXG4gICAgLy8gRm9yIHB1YmxpYyBrZXkgdGhlIGJvb2xlYW4gJ3B1YmxpY0tleScgaXMgdHJ1ZS5cbiAgICAvLyBGb3IgcHJpdmF0ZSBrZXkgdGhlIGJvb2xlYW4gJ3B1YmxpY0tleScgaXMgZmFsc2UuXG4gICAgLy8gSWYgdGhlIGtleSBpcyB1c2VkIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gdGhlbiB0aGUgYm9vbGVhbiAnZW5jcnlwdGlvbicgaXMgdHJ1ZS5cbiAgICAvLyBJZiB0aGUga2V5IGlzIHVzZWQgZm9yIHNpZ25hdHVyZS9zaWduYXR1cmUgdmVyaWZpY2F0aW9uIHRoZW4gdGhlIGJvb2xlYW4gaXMgZmFsc2UuXG4gICAgY29uc3Qga2V5UmVxdWVzdE1lc3NhZ2UgPVxuICAgICAgICBuZXcgS2V5UmVxdWVzdCh1c2VyLCBwdWJsaWNLZXksIGVuY3J5cHRpb24pXG4gICAgLy8gRm9yIENBUyBhdXRoZW50aWNhdGlvbiB3ZSBuZWVkIHRvIGFkZCB0aGUgYXV0aGVudGljYXRpb24gdGlja2V0XG4gICAgLy8gSXQgaXMgY29udGFpbmVkIGluIHVybFBhcmFtc1xuICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgLy8gRm9yIGdldHRpbmcgYSBrZXkgd2UgZG8gbm90IG5lZWQgdGhlIG93bmVyTmFtZSBwYXJhbVxuICAgIC8vIEJlY2F1c2Uga2V5cyBhcmUgaW5kZXBlbmRhbnQgb2YgdGhlIGFwcGxpY2F0aW9uc1xuICAgIGNvbnN0IGtleXJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9nZXRLZXk/XCIgKyB1cmxQYXJhbXMsIHtcbiAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoa2V5UmVxdWVzdE1lc3NhZ2UpLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICB9XG4gICAgfSk7XG4gICAgaWYgKCFrZXlyZXF1ZXN0Lm9rKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtrZXlyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICB9XG4gICAgY29uc3Qga2V5UmVzdWx0ID0gKGF3YWl0IGtleXJlcXVlc3QuanNvbigpKSBhcyBLZXlSZXN1bHQ7XG4gICAgaWYgKCFrZXlSZXN1bHQuc3VjY2VzcykgYWxlcnQoa2V5UmVzdWx0LmVycm9yTWVzc2FnZSlcbiAgICBlbHNlIHtcbiAgICAgICAgaWYgKHB1YmxpY0tleSAmJiBlbmNyeXB0aW9uKSByZXR1cm4gYXdhaXQgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKGtleVJlc3VsdC5rZXkpXG4gICAgICAgIGVsc2UgaWYgKCFwdWJsaWNLZXkgJiYgZW5jcnlwdGlvbikgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHJpdmF0ZUtleUZvckVuY3J5cHRpb24oa2V5UmVzdWx0LmtleSlcbiAgICAgICAgZWxzZSBpZiAocHVibGljS2V5ICYmICFlbmNyeXB0aW9uKSByZXR1cm4gYXdhaXQgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUoa2V5UmVzdWx0LmtleSlcbiAgICAgICAgZWxzZSBpZiAoIXB1YmxpY0tleSAmJiAhZW5jcnlwdGlvbikgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHJpdmF0ZUtleUZvclNpZ25hdHVyZShrZXlSZXN1bHQua2V5KVxuICAgIH1cbn1cblxuXG5hc3luYyBmdW5jdGlvbiBzZW5kTWVzc2FnZShhZ2VudE5hbWU6IHN0cmluZywgcmVjZWl2ZXJOYW1lOiBzdHJpbmcsIG1lc3NhZ2VDb250ZW50OiBzdHJpbmcpOiBQcm9taXNlPFNlbmRSZXN1bHQ+IHtcbiAgICB0cnkge1xuICAgICAgICBsZXQgbWVzc2FnZVRvU2VuZCA9XG4gICAgICAgICAgICBuZXcgRXh0TWVzc2FnZShhZ2VudE5hbWUsIHJlY2VpdmVyTmFtZSwgbWVzc2FnZUNvbnRlbnQpXG4gICAgICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG5cbiAgICAgICAgY29uc3QgcmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL3NlbmRpbmdNZXNzYWdlL1wiICsgb3duZXJOYW1lICsgXCI/XCIgKyB1cmxQYXJhbXMsIHtcbiAgICAgICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShtZXNzYWdlVG9TZW5kKSxcbiAgICAgICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgaWYgKCFyZXF1ZXN0Lm9rKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7cmVxdWVzdC5zdGF0dXN9YCk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gRGVhbGluZyB3aXRoIHRoZSBhbnN3ZXIgb2YgdGhlIG1lc3NhZ2Ugc2VydmVyXG4gICAgICAgIHJldHVybiAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIFNlbmRSZXN1bHRcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZXJyb3IgbWVzc2FnZTogJywgZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlbmRSZXN1bHQoZmFsc2UsIGVycm9yLm1lc3NhZ2UpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygndW5leHBlY3RlZCBlcnJvcjogJywgZXJyb3IpO1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBTZW5kUmVzdWx0KGZhbHNlLCAnQW4gdW5leHBlY3RlZCBlcnJvciBvY2N1cnJlZCcpXG4gICAgICAgIH1cbiAgICB9XG59XG5cbi8vIERldGVjdCB3aGVuIHRoZSBFbnRlciBrZXkgaXMgcHJlc3NlZCBpbiB0aGUgbWVzc2FnZSBmaWVsZC5cbi8vIElmIHNvLCB3ZSBjbGljayBvbiB0aGUgXCJzZW5kXCIgYnV0dG9uLlxubWVzc2FnZS5hZGRFdmVudExpc3RlbmVyKFwia2V5dXBcIiwgZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgaWYgKGV2ZW50LmtleSA9PT0gXCJFbnRlclwiKSB7XG4gICAgICAgIHNlbmRCdXR0b24uY2xpY2soKVxuICAgIH1cbn0pO1xuXG5zZW5kQnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgbGV0IGFnZW50TmFtZSA9IGdsb2JhbFVzZXJOYW1lXG4gICAgbGV0IHJlY2VpdmVyTmFtZSA9IHJlY2VpdmVyLnZhbHVlXG4gICAgbGV0IGNvbnRlbnRUb0VuY3J5cHQgPSBKU09OLnN0cmluZ2lmeShbYWdlbnROYW1lLCBtZXNzYWdlLnZhbHVlXSlcbiAgICAvLyB3ZSBmZXRjaCB0aGUgcHVibGljIGtleSBvZiBCXG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2IgPSBhd2FpdCBmZXRjaEtleShyZWNlaXZlck5hbWUsIHRydWUsIHRydWUpXG4gICAgICAgIC8vIFdlIGVuY3J5cHRcbiAgICAgICAgY29uc3QgZW5jcnlwdGVkTWVzc2FnZSA9IGF3YWl0IGVuY3J5cHRXaXRoUHVibGljS2V5KGtiLCBjb250ZW50VG9FbmNyeXB0KVxuICAgICAgICAvLyBBbmQgc2VuZFxuICAgICAgICBjb25zdCBzZW5kUmVzdWx0ID0gYXdhaXQgc2VuZE1lc3NhZ2UoYWdlbnROYW1lLCByZWNlaXZlck5hbWUsIGVuY3J5cHRlZE1lc3NhZ2UpXG4gICAgICAgIGlmICghc2VuZFJlc3VsdC5zdWNjZXNzKSBjb25zb2xlLmxvZyhzZW5kUmVzdWx0LmVycm9yTWVzc2FnZSlcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlN1Y2Nlc3NmdWxseSBzZW50IHRoZSBtZXNzYWdlIVwiKVxuICAgICAgICAgICAgLy8gV2UgYWRkIHRoZSBtZXNzYWdlIHRvIHRoZSBsaXN0IG9mIHNlbnQgbWVzc2FnZXNcbiAgICAgICAgICAgIGNvbnN0IHRleHRUb0FkZCA9IGA8Zm9udCBjb2xvcj1cImJsdWVcIj4gJHthZ2VudE5hbWV9IC0+ICR7cmVjZWl2ZXJOYW1lfSA6ICgke3JlYWRhYmxlVGltZSgpfSkgJHttZXNzYWdlLnZhbHVlfSA8L2ZvbnQ+YFxuICAgICAgICAgICAgYWRkaW5nUmVjZWl2ZWRNZXNzYWdlKHRleHRUb0FkZClcbiAgICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBFcnJvcikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coJ2Vycm9yIG1lc3NhZ2U6ICcsIGUubWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlKTtcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLy8gUmV0dXJuaW5nIGEgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgY3VycmVudCB0aW1lIGluIHRoZSBmb3JtYXRcbi8vIEhIOk1NOlNTXG5mdW5jdGlvbiByZWFkYWJsZVRpbWUoKTogc3RyaW5nIHtcbiAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpXG4gICAgY29uc3QgaG91cnMgPSBub3cuZ2V0SG91cnMoKS50b1N0cmluZygpXG4gICAgY29uc3QgbWludXRlcyA9IG5vdy5nZXRNaW51dGVzKCkudG9TdHJpbmcoKVxuICAgIGNvbnN0IHNlY29uZHMgPSBub3cuZ2V0U2Vjb25kcygpLnRvU3RyaW5nKClcbiAgICAvLyBTaW5jZSBnZXRIb3VycygpIGV0YyByZXR1cm4gYSBkZWNpbWFsIGNvdW50IGZvciBob3VycywgZXRjLiB3ZSBleHBsaWNpdGVseSBhZGQgMCB3aGVuIHRoZXJlXG4gICAgLy8gYXJlIG5vIHRlbnMgZGlnaXQuXG4gICAgcmV0dXJuIGAkeyhob3Vycy5sZW5ndGggPT09IDEpID8gXCIwXCIgKyBob3VycyA6IGhvdXJzfTokeyhtaW51dGVzLmxlbmd0aCA9PT0gMSkgPyBcIjBcIiArIG1pbnV0ZXMgOiBtaW51dGVzfTokeyhzZWNvbmRzLmxlbmd0aCA9PT0gMSkgPyBcIjBcIiArIHNlY29uZHMgOiBzZWNvbmRzfWBcbn1cblxuLy8gUGFyc2luZy9SZWNvZ25pemluZyBhIG1lc3NhZ2Ugc2VudCB0byBhcHBfdXNlclxuLy8gVGhlIGZpcnN0IGVsZW1lbnQgb2YgdGhlIHR1cGxlIGlzIGEgYm9vbGVhbiBzYXlpbmcgaWYgdGhlIG1lc3NhZ2Ugd2FzIGZvciB0aGUgdXNlclxuLy8gSWYgdGhpcyBib29sZWFuIGlzIHRydWUsIHRoZW4gdGhlIHNlY29uZCBlbGVtZW50IGlzIHRoZSBuYW1lIG9mIHRoZSBzZW5kZXJcbi8vIGFuZCB0aGUgdGhpcmQgaXMgdGhlIGNvbnRlbnQgb2YgdGhlIG1lc3NhZ2VcbmFzeW5jIGZ1bmN0aW9uIGFuYWx5c2VNZXNzYWdlKG1lc3NhZ2U6IEV4dE1lc3NhZ2UpOiBQcm9taXNlPFtib29sZWFuLCBzdHJpbmcsIHN0cmluZ10+IHtcbiAgICBjb25zdCB1c2VyID0gZ2xvYmFsVXNlck5hbWVcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlU2VuZGVyID0gbWVzc2FnZS5zZW5kZXJcbiAgICAgICAgY29uc3QgbWVzc2FnZUNvbnRlbnQgPSBtZXNzYWdlLmNvbnRlbnRcbiAgICAgICAgaWYgKG1lc3NhZ2UucmVjZWl2ZXIgIT09IHVzZXIpIHtcbiAgICAgICAgICAgIC8vIElmIHRoZSBtZXNzYWdlIGlzIG5vdCBzZW50IHRvIHRoZSB1c2VyLCB3ZSBkbyBub3QgY29uc2lkZXIgaXRcbiAgICAgICAgICAgIHJldHVybiBbZmFsc2UsIFwiXCIsIFwiXCJdXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAvL3dlIGZldGNoIHVzZXIgcHJpdmF0ZSBrZXkgdG8gZGVjcnlwdCB0aGUgbWVzc2FnZVxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBjb25zdCBwcml2a2V5ID0gYXdhaXQgZmV0Y2hLZXkodXNlciwgZmFsc2UsIHRydWUpXG4gICAgICAgICAgICAgICAgY29uc3QgbWVzc2FnZUluQ2xlYXJTdHJpbmcgPSBhd2FpdCBkZWNyeXB0V2l0aFByaXZhdGVLZXkocHJpdmtleSwgbWVzc2FnZUNvbnRlbnQpXG4gICAgICAgICAgICAgICAgY29uc3QgbWVzc2FnZUFycmF5SW5DbGVhciA9IEpTT04ucGFyc2UobWVzc2FnZUluQ2xlYXJTdHJpbmcpIGFzIHN0cmluZ1tdXG4gICAgICAgICAgICAgICAgY29uc3QgbWVzc2FnZVNlbmRlckluTWVzc2FnZSA9IG1lc3NhZ2VBcnJheUluQ2xlYXJbMF1cbiAgICAgICAgICAgICAgICBjb25zdCBtZXNzYWdlSW5DbGVhciA9IG1lc3NhZ2VBcnJheUluQ2xlYXJbMV1cbiAgICAgICAgICAgICAgICBpZiAobWVzc2FnZVNlbmRlckluTWVzc2FnZSA9PSBtZXNzYWdlU2VuZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBbdHJ1ZSwgbWVzc2FnZVNlbmRlciwgZXZhbChcImAoJHtyZWFkYWJsZVRpbWUoKX0pIFwiICsgbWVzc2FnZUluQ2xlYXIgKyBcImBcIildXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcIlJlYWwgbWVzc2FnZSBzZW5kZXIgYW5kIG1lc3NhZ2Ugc2VuZGVyIG5hbWUgaW4gdGhlIG1lc3NhZ2UgZG8gbm90IGNvaW5jaWRlXCIpXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiYW5hbHlzZU1lc3NhZ2U6IGRlY3J5cHRpb24gZmFpbGVkIGJlY2F1c2Ugb2YgXCIgKyBlKVxuICAgICAgICAgICAgICAgIHJldHVybiBbZmFsc2UsIFwiXCIsIFwiXCJdXG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiYW5hbHlzZU1lc3NhZ2U6IGRlY3J5cHRpb24gZmFpbGVkIGJlY2F1c2Ugb2YgXCIgKyBlKVxuICAgICAgICByZXR1cm4gW2ZhbHNlLCBcIlwiLCBcIlwiXVxuICAgIH1cbn1cblxuLy8gYWN0aW9uIGZvciByZWNlaXZpbmcgbWVzc2FnZSBcbi8vIDEuIEEgLT4gQjoge0EsbWVzc2FnZX1LYiAgICAgXG5mdW5jdGlvbiBhY3Rpb25Pbk1lc3NhZ2VPbmUoZnJvbUE6IHN0cmluZywgbWVzc2FnZUNvbnRlbnQ6IHN0cmluZykge1xuICAgIGNvbnN0IHVzZXIgPSBnbG9iYWxVc2VyTmFtZVxuICAgIGNvbnN0IHRleHRUb0FkZCA9IGAke2Zyb21BfSAtPiAke3VzZXJ9IDogJHttZXNzYWdlQ29udGVudH0gYFxuICAgIGFkZGluZ1JlY2VpdmVkTWVzc2FnZSh0ZXh0VG9BZGQpXG59XG5cbi8vIGZ1bmN0aW9uIGZvciByZWZyZXNoaW5nIHRoZSBjb250ZW50IG9mIHRoZSB3aW5kb3cgKGF1dG9tYXRpYyBvciBtYW51YWwgc2VlIGJlbG93KVxuYXN5bmMgZnVuY3Rpb24gcmVmcmVzaCgpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB1c2VyID0gZ2xvYmFsVXNlck5hbWVcbiAgICAgICAgY29uc3QgaGlzdG9yeVJlcXVlc3QgPVxuICAgICAgICAgICAgbmV3IEhpc3RvcnlSZXF1ZXN0KHVzZXIsIGxhc3RJbmRleEluSGlzdG9yeSlcbiAgICAgICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcbiAgICAgICAgY29uc3QgcmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL2hpc3RvcnkvXCIgKyBvd25lck5hbWUgKyBcIj9cIiArIHVybFBhcmFtc1xuICAgICAgICAgICAgLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShoaXN0b3J5UmVxdWVzdCksXG4gICAgICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c30gYCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVzdWx0ID0gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBIaXN0b3J5QW5zd2VyXG4gICAgICAgIGlmICghcmVzdWx0LnN1Y2Nlc3MpIHsgYWxlcnQocmVzdWx0LmZhaWx1cmVNZXNzYWdlKSB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgLy8gV2UgdXBkYXRlIHRoZSBpbmRleCB3aXRoIHRoZSBpbmRleCBvZiBsYXN0IHJlYWQgbWVzc2FnZSBmcm9tIG1lc3NhZ2Ugc2VydmVyXG4gICAgICAgICAgICBsYXN0SW5kZXhJbkhpc3RvcnkgPSByZXN1bHQuaW5kZXhcbiAgICAgICAgICAgIGlmIChyZXN1bHQuYWxsTWVzc2FnZXMubGVuZ3RoICE9IDApIHtcbiAgICAgICAgICAgICAgICBmb3IgKHZhciBtIG9mIHJlc3VsdC5hbGxNZXNzYWdlcykge1xuICAgICAgICAgICAgICAgICAgICBsZXQgW2IsIHNlbmRlciwgbXNnQ29udGVudF0gPSBhd2FpdCBhbmFseXNlTWVzc2FnZShtKVxuICAgICAgICAgICAgICAgICAgICBpZiAoYikgYWN0aW9uT25NZXNzYWdlT25lKHNlbmRlciwgbXNnQ29udGVudClcbiAgICAgICAgICAgICAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIk1zZyBcIiArIG0gKyBcIiBjYW5ub3QgYmUgZXhwbG9pdGVkIGJ5IFwiICsgdXNlcilcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZXJyb3IgbWVzc2FnZTogJywgZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm4gZXJyb3IubWVzc2FnZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnO1xuICAgICAgICB9XG4gICAgfVxufVxuXG4vLyBBdXRvbWF0aWMgcmVmcmVzaFxuY29uc3QgaW50ZXJ2YWxSZWZyZXNoID0gc2V0SW50ZXJ2YWwocmVmcmVzaCwgMjAwMClcblxuXG4iXSwKICAibWFwcGluZ3MiOiAiO0FBMENBLGVBQXNCLCtCQUErQixZQUF3QztBQUN6RixNQUFJO0FBQ0EsVUFBTSxpQkFBOEIsMEJBQTBCLFVBQVU7QUFDeEUsVUFBTSxNQUFpQixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsTUFDOUM7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLFFBQ0ksTUFBTTtBQUFBLFFBQ04sTUFBTTtBQUFBLE1BQ1Y7QUFBQSxNQUNBO0FBQUEsTUFDQSxDQUFDLFNBQVM7QUFBQSxJQUNkO0FBQ0EsV0FBTztBQUFBLEVBQ1gsU0FBUyxHQUFHO0FBQ1Is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O0FBRUQsMkJBQXFCLE9BQU87QUFDNUIsVUFBSSxPQUFPLFlBQVksVUFBVSxHQUFHO0FBQ2hDLGlCQUFTLEtBQUssT0FBTyxhQUFhO0FBQzlCLGNBQUksQ0FBQyxHQUFHLFFBQVEsVUFBVSxJQUFJLE1BQU0sZUFBZSxDQUFDO0FBQ3BELGNBQUksRUFBRyxvQkFBbUIsUUFBUSxVQUFVO0FBQUEsY0FDdkMsU0FBUSxJQUFJLFNBQVMsSUFBSSw2QkFBNkJBLEtBQUk7QUFBQSxRQUNuRTtBQUFBLE1BQ0o7QUFBQSxJQUNKO0FBQUEsRUFDSixTQUNPLE9BQU87QUFDVixRQUFJLGlCQUFpQixPQUFPO0FBQ3hCLGNBQVEsSUFBSSxtQkFBbUIsTUFBTSxPQUFPO0FBQzVDLGFBQU8sTUFBTTtBQUFBLElBQ2pCLE9BQU87QUFDSCxjQUFRLElBQUksc0JBQXNCLEtBQUs7QUFDdkMsYUFBTztBQUFBLElBQ1g7QUFBQSxFQUNKO0FBQ0o7QUFHQSxJQUFNLGtCQUFrQixZQUFZLFNBQVMsR0FBSTsiLAogICJuYW1lcyI6IFsibWVzc2FnZSIsICJtZXNzYWdlSW5DbGVhciIsICJtZXNzYWdlIiwgInJlY2VpdmVyIiwgIm1lc3NhZ2UiLCAidXNlciIsICJtZXNzYWdlQ29udGVudCJdCn0K
