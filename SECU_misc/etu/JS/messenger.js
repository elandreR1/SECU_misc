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
async function encryptWithPublicKey(publicKey, message2) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message2);
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
async function signWithPrivateKey(privateKey, message2) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message2);
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
async function decryptWithPrivateKey(privateKey, message2) {
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64StringToArrayBuffer(message2)
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
async function encryptWithSymmetricKey(key, message2) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message2);
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
async function decryptWithSymmetricKey(key, message2, initVector) {
  const decodedInitVector = base64StringToArrayBuffer(initVector);
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodedInitVector },
      key,
      base64StringToArrayBuffer(message2)
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
  constructor(message2, index, deleted, deleter) {
    this.message = message2;
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
  constructor(success, message2) {
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

// src/messenger.ts
if (!window.isSecureContext) alert("Not secure context!");
var lastIndexInHistory = 0;
var userButtonLabel = document.getElementById("user-name");
var sendButton = document.getElementById("send-button");
var receiver = document.getElementById("receiver");
var message = document.getElementById("message");
var received_messages = document.getElementById("exchanged-messages");
function clearingMessages() {
  received_messages.textContent = "";
}
function stringToHTML(str) {
  var div_elt = document.createElement("div");
  div_elt.innerHTML = str;
  return div_elt;
}
function addingReceivedMessage(message2) {
  received_messages.append(stringToHTML("<p></p><p></p>" + message2));
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
  loadNonces();
}
setCasName();
function getOwnerName() {
  const path = window.location.pathname;
  const name = path.split("/", 2)[1];
  return name;
}
var ownerName = getOwnerName();
var keyCache = {};
async function fetchKey(user, publicKey, encryption) {
  const keyId = `${user}-${publicKey ? "pub" : "priv"}-${encryption ? "enc" : "sig"}`;
  if (keyCache[keyId]) {
    return keyCache[keyId];
  }
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
  if (!keyResult.success) throw new Error(keyResult.errorMessage);
  let key;
  if (publicKey && encryption) key = await stringToPublicKeyForEncryption(keyResult.key);
  else if (!publicKey && encryption) key = await stringToPrivateKeyForEncryption(keyResult.key);
  else if (publicKey && !encryption) key = await stringToPublicKeyForSignature(keyResult.key);
  else key = await stringToPrivateKeyForSignature(keyResult.key);
  keyCache[keyId] = key;
  return key;
}
async function sendMessage(agentName, receiverName, messageContent) {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
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
async function refresh() {
  try {
    const user = globalUserName;
    const historyRequest = new HistoryRequest(user, lastIndexInHistory);
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
      for (const m of result.allMessages) {
        const [isValid, sender, clearMessage] = await analyseMessage(m);
        if (isValid) {
          addingReceivedMessage(`${sender} -> ${user} : ${clearMessage}`);
        } else {
          console.log("Message invalide ou non d\xE9chiffrable");
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
var verifNonce = {};
function saveNonces() {
  localStorage.setItem("nonces", JSON.stringify(verifNonce));
}
function loadNonces() {
  const stored = localStorage.getItem("nonces");
  if (stored) Object.assign(verifNonce, JSON.parse(stored));
}
sendButton.onclick = async function() {
  const agentName = globalUserName;
  const receiverName = receiver.value.trim();
  const msg = message.value.trim();
  if (receiverName === "" || msg === "") {
    alert("Veuillez remplir tous les champs.");
    return;
  }
  try {
    const nonce = generateNonce();
    verifNonce[nonce] = {
      receiver: receiverName,
      message: msg
    };
    saveNonces();
    const payload = {
      msg,
      nonce
    };
    const receiverPublicKey = await fetchKey(receiverName, true, true);
    const encryptedMessage = await encryptWithPublicKey(receiverPublicKey, JSON.stringify(payload));
    const signMessage = await fetchKey(agentName, false, false);
    const MessSign = await signWithPrivateKey(signMessage, encryptedMessage);
    const signetMess = JSON.stringify({
      encrypted: encryptedMessage,
      signature: MessSign
    });
    const sendResult = await sendMessage(agentName, receiverName, signetMess);
    if (!sendResult.success) {
      console.log(sendResult.errorMessage);
    } else {
      console.log("Message envoy\xE9 avec succ\xE8s");
      const time = readableTime();
      const textToAdd = `<font color="blue"> ${agentName} -> ${receiverName} : (${time}) ${msg} </font>`;
      addingReceivedMessage(textToAdd);
      message.value = "";
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
async function analyseMessage(message2) {
  const user = globalUserName;
  const sender = message2.sender;
  const content = message2.content;
  if (message2.receiver !== user) return [false, "", ""];
  try {
    const parsedAck = JSON.parse(content);
    if (parsedAck.encrypted && !parsedAck.signature) {
      const encryptedAck = parsedAck.encrypted;
      const privateKey = await fetchKey(user, false, true);
      const decryptedNonce = await decryptWithPrivateKey(privateKey, encryptedAck);
      const expected = verifNonce[decryptedNonce];
      if (expected && expected.receiver === sender) {
        delete verifNonce[decryptedNonce];
        saveNonces();
        return [true, sender, `${readableTime()} - le message a \xE9t\xE9 envoy\xE9 et re\xE7u \xE0 ${readableTime()}`];
      } else {
        console.log("ACK re\xE7u avec nonce inconnu :", decryptedNonce);
        return [false, "", ""];
      }
    }
  } catch (e) {
  }
  try {
    const parsedMsg = JSON.parse(content);
    const { encrypted, signature } = parsedMsg;
    if (!encrypted || !signature) {
      console.log("Message mal form\xE9 (manque encrypted ou signature)");
      return [false, "", ""];
    }
    const senderPubKey = await fetchKey(sender, true, false);
    const valid = await verifySignatureWithPublicKey(senderPubKey, encrypted, signature);
    if (!valid) {
      console.log("Signature non valide");
      return [false, "", ""];
    }
    const privateKey = await fetchKey(user, false, true);
    const decrypted = await decryptWithPrivateKey(privateKey, encrypted);
    const payload = JSON.parse(decrypted);
    const msg = payload.msg;
    const nonce = payload.nonce;
    if (!msg || !nonce) {
      console.log("Payload incomplet :", payload);
      return [false, "", ""];
    }
    await sendAcknowledgment(user, sender, nonce);
    return [true, sender, `${readableTime()} - ${msg}`];
  } catch (e) {
    console.error("Erreur dans analyseMessage :", e);
    return [false, "", ""];
  }
}
async function sendAcknowledgment(receiver2, sender, nonce) {
  try {
    const senderPublicKey = await fetchKey(sender, true, true);
    const encryptedAck = await encryptWithPublicKey(senderPublicKey, nonce);
    const ackMessage = JSON.stringify({
      encrypted: encryptedAck
    });
    const sendResult = await sendMessage(receiver2, sender, ackMessage);
    if (!sendResult.success) {
      console.log(" \xC9chec de l'envoi du ACK :", sendResult.errorMessage);
    } else {
      console.log(" ACK envoy\xE9 \xE0", sender);
    }
  } catch (e) {
    console.error("Erreur dans sendAcknowledgment :", e);
  }
}
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvc2VydmVyTWVzc2FnZXMudHMiLCAiLi4vc3JjL21lc3Nlbmdlci50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiLyogU291cmNlOiBodHRwczovL2dpc3QuZ2l0aHViLmNvbS9ncm91bmRyYWNlL2I1MTQxMDYyYjQ3ZGQ5NmE1YzIxYzkzODM5ZDRiOTU0ICovXG5cbi8qIEF2YWlsYWJsZSBmdW5jdGlvbnM6XG5cbiAgICAjIEtleS9ub25jZSBnZW5lcmF0aW9uOlxuICAgIGdlbmVyYXRlQXNzeW1ldHJpY0tleXNGb3JFbmNyeXB0aW9uKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvclNpZ25hdHVyZSgpOiBQcm9taXNlPENyeXB0b0tleVtdPlxuICAgIGdlbmVyYXRlU3ltZXRyaWNLZXkoKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmdcblxuICAgICMgQXNzeW1ldHJpYyBrZXkgRW5jcnlwdGlvbi9EZWNyeXB0aW9uL1NpZ25hdHVyZS9TaWduYXR1cmUgdmVyaWZpY2F0aW9uXG4gICAgZW5jcnlwdFdpdGhQdWJsaWNLZXkocGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiAgICBkZWNyeXB0V2l0aFByaXZhdGVLZXkoc2tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzaWduV2l0aFByaXZhdGVLZXkocHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiAgICB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlSW5DbGVhcjogc3RyaW5nLCBzaWduZWRNZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+XG5cbiAgICAjIFN5bW1ldHJpYyBrZXkgRW5jcnlwdGlvbi9EZWNyeXB0aW9uXG4gICAgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nW10+XG4gICAgZGVjcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZywgaW5pdFZlY3Rvcjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+XG5cbiAgICAjIEltcG9ydGluZyBrZXlzIGZyb20gc3RyaW5nXG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKHBrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbihza2V5SW5CYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PlxuICAgIHN0cmluZ1RvUHVibGljS2V5Rm9yU2lnbmF0dXJlKHBrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9TeW1tZXRyaWNLZXkoc2tleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG5cbiAgICAjIEV4cG9ydGluZyBrZXlzIHRvIHN0cmluZ1xuICAgIHB1YmxpY0tleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+XG4gICAgcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+XG4gICAgc3ltbWV0cmljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSGFzaGluZ1xuICAgIGhhc2godGV4dDogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+XG4qL1xuXG4vLyBMaWJDcnlwdG8tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBmcm9tIHRoZSBpbXBvcnQgc3BhY2UuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKHBrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihwa2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwic3BraVwiLFxuICAgICAgICAgICAga2V5QXJyYXlCdWZmZXIsXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbmFtZTogXCJSU0EtT0FFUFwiLFxuICAgICAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHRydWUsXG4gICAgICAgICAgICBbXCJlbmNyeXB0XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHB1YmxpYyBrZXkgKGZvciBzaWduYXR1cmUgdmVyaWZpY2F0aW9uKSBmcm9tIHRoZSBpbXBvcnQgc3BhY2UuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcInZlcmlmeVwiXVxuICAgICAgICApXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBzaWduYXR1cmUgdmVyaWZpY2F0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8qXG5JbXBvcnRzIHRoZSBnaXZlbiBwcml2YXRlIGtleSAoaW4gc3RyaW5nKSBhcyBhIHZhbGlkIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbilcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbihza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2tleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInBrY3M4XCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImRlY3J5cHRcIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInBrY3M4XCIgPz8gZm9ybWF0IGZvciBpbXBvcnRpbmcgcHVibGljIGtleXMuXG4qL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN0cmluZ1RvUHJpdmF0ZUtleUZvclNpZ25hdHVyZShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2tleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInBrY3M4XCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcInNpZ25cIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3Igc2lnbmF0dXJlKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG4vKlxuRXhwb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSBpbnRvIGEgdmFsaWQgc3RyaW5nLlxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJzcGtpXCIgZm9ybWF0IGZvciBleHBvcnRpbmcgcHVibGljIGtleXMuXG4qL1xuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGV4cG9ydGVkS2V5OiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmV4cG9ydEtleShcInNwa2lcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKlxuRXhwb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSBpbnRvIGEgdmFsaWQgc3RyaW5nLlxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJzcGtpXCIgZm9ybWF0IGZvciBleHBvcnRpbmcgcHVibGljIGtleXMuXG4qL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHByaXZhdGVLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwicGtjczhcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3IgZW5jcnlwdGlvbi9kZWNyeXB0aW9uICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT4ge1xuICAgIGNvbnN0IGtleXBhaXI6IENyeXB0b0tleVBhaXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShcbiAgICAgICAge1xuICAgICAgICAgICAgbmFtZTogXCJSU0EtT0FFUFwiLFxuICAgICAgICAgICAgbW9kdWx1c0xlbmd0aDogMjA0OCxcbiAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMSwgMCwgMV0pLFxuICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgIH0sXG4gICAgICAgIHRydWUsXG4gICAgICAgIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcGFpciBvZiBwdWJsaWMgYW5kIHByaXZhdGUgUlNBIGtleXMgZm9yIHNpZ25pbmcvdmVyaWZ5aW5nICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVBc3N5bWV0cmljS2V5c0ZvclNpZ25hdHVyZSgpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wic2lnblwiLCBcInZlcmlmeVwiXVxuICAgIClcbiAgICByZXR1cm4gW2tleXBhaXIucHVibGljS2V5LCBrZXlwYWlyLnByaXZhdGVLZXldXG59XG5cbi8qIEdlbmVyYXRlcyBhIHJhbmRvbSBub25jZSAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdlbmVyYXRlTm9uY2UoKTogc3RyaW5nIHtcbiAgICBjb25zdCBub25jZUFycmF5ID0gbmV3IFVpbnQzMkFycmF5KDEpXG4gICAgc2VsZi5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5vbmNlQXJyYXkpXG4gICAgcmV0dXJuIG5vbmNlQXJyYXlbMF0udG9TdHJpbmcoKVxufVxuXG4vKiBFbmNyeXB0cyBhIG1lc3NhZ2Ugd2l0aCBhIHB1YmxpYyBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBlbmNyeXB0V2l0aFB1YmxpY0tleShwdWJsaWNLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IGN5cGhlcmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmVuY3J5cHQoXG4gICAgICAgICAgICB7IG5hbWU6IFwiUlNBLU9BRVBcIiB9LFxuICAgICAgICAgICAgcHVibGljS2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhjeXBoZXJlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIkVuY3J5cHRpb24gZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJQdWJsaWMga2V5IG9yIG1lc3NhZ2UgdG8gZW5jcnlwdCBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLyogU2lnbiBhIG1lc3NhZ2Ugd2l0aCBhIHByaXZhdGUga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2lnbldpdGhQcml2YXRlS2V5KHByaXZhdGVLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IHNpZ25lZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5zaWduKFxuICAgICAgICAgICAgXCJSU0FTU0EtUEtDUzEtdjFfNVwiLFxuICAgICAgICAgICAgcHJpdmF0ZUtleSxcbiAgICAgICAgICAgIG1lc3NhZ2VUb0FycmF5QnVmZmVyXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoc2lnbmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiU2lnbmF0dXJlIGZhaWxlZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiUHJpdmF0ZSBrZXkgb3IgbWVzc2FnZSB0byBzaWduIGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIERlY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHJpdmF0ZSBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWNyeXB0V2l0aFByaXZhdGVLZXkocHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGRlY3J5dHBlZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdFxuICAgICAgICAgICAgd2luZG93LmNyeXB0by5zdWJ0bGUuZGVjcnlwdChcbiAgICAgICAgICAgICAgICB7IG5hbWU6IFwiUlNBLU9BRVBcIiB9LFxuICAgICAgICAgICAgICAgIHByaXZhdGVLZXksXG4gICAgICAgICAgICAgICAgYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb1RleHQoZGVjcnl0cGVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiSW52YWxpZCBrZXksIG1lc3NhZ2Ugb3IgYWxnb3JpdGhtIGZvciBkZWNyeXB0aW9uXCIpXG4gICAgICAgIH0gZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJQcml2YXRlIGtleSBvciBtZXNzYWdlIHRvIGRlY3J5cHQgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIFZlcmlmaWNhdGlvbiBvZiBhIHNpZ25hdHVyZSBvbiBhIG1lc3NhZ2Ugd2l0aCBhIHB1YmxpYyBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlSW5DbGVhcjogc3RyaW5nLCBzaWduZWRNZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBzaWduZWRUb0FycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihzaWduZWRNZXNzYWdlKVxuICAgICAgICBjb25zdCBtZXNzYWdlSW5DbGVhclRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlSW5DbGVhcilcbiAgICAgICAgY29uc3QgdmVyaWZpZWQ6IGJvb2xlYW4gPSBhd2FpdFxuICAgICAgICAgICAgd2luZG93LmNyeXB0by5zdWJ0bGUudmVyaWZ5KFxuICAgICAgICAgICAgICAgIFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICAgICAgc2lnbmVkVG9BcnJheUJ1ZmZlcixcbiAgICAgICAgICAgICAgICBtZXNzYWdlSW5DbGVhclRvQXJyYXlCdWZmZXIpXG4gICAgICAgIHJldHVybiB2ZXJpZmllZFxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiSW52YWxpZCBrZXksIG1lc3NhZ2Ugb3IgYWxnb3JpdGhtIGZvciBzaWduYXR1cmUgdmVyaWZpY2F0aW9uXCIpXG4gICAgICAgIH0gZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJQdWJsaWMga2V5IG9yIHNpZ25lZCBtZXNzYWdlIHRvIHZlcmlmeSBpcyBpbGwtZm9ybWVkXCIpXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cblxuLyogR2VuZXJhdGVzIGEgc3ltbWV0cmljIEFFUy1HQ00ga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiQUVTLUdDTVwiLFxuICAgICAgICAgICAgbGVuZ3RoOiAyNTYsXG4gICAgICAgIH0sXG4gICAgICAgIHRydWUsXG4gICAgICAgIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdXG4gICAgKVxuICAgIHJldHVybiBrZXlcbn1cblxuLyogYSBzeW1tZXRyaWMgQUVTIGtleSBpbnRvIGEgc3RyaW5nICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3ltbWV0cmljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGV4cG9ydGVkS2V5OiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmV4cG9ydEtleShcInJhd1wiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEltcG9ydHMgdGhlIGdpdmVuIGtleSAoaW4gc3RyaW5nKSBhcyBhIHZhbGlkIEFFUyBrZXkgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2tleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInJhd1wiLFxuICAgICAgICAgICAga2V5QXJyYXlCdWZmZXIsXG4gICAgICAgICAgICBcIkFFUy1HQ01cIixcbiAgICAgICAgICAgIHRydWUsXG4gICAgICAgICAgICBbXCJlbmNyeXB0XCIsIFwiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBzeW1tZXRyaWMga2V5IGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHN5bW1ldHJpYyBrZXkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8vIFdoZW4gY3lwaGVyaW5nIGEgbWVzc2FnZSB3aXRoIGEga2V5IGluIEFFUywgd2Ugb2J0YWluIGEgY3lwaGVyZWQgbWVzc2FnZSBhbmQgYW4gXCJpbml0aWFsaXNhdGlvbiB2ZWN0b3JcIi5cbi8vIEluIHRoaXMgaW1wbGVtZW50YXRpb24sIHRoZSBvdXRwdXQgaXMgYSB0d28gZWxlbWVudHMgYXJyYXkgdCBzdWNoIHRoYXQgdFswXSBpcyB0aGUgY3lwaGVyZWQgbWVzc2FnZVxuLy8gYW5kIHRbMV0gaXMgdGhlIGluaXRpYWxpc2F0aW9uIHZlY3Rvci4gVG8gc2ltcGxpZnksIHRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3IgaXMgcmVwcmVzZW50ZWQgYnkgYSBzdHJpbmcuXG4vLyBUaGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yZSBpcyB1c2VkIGZvciBwcm90ZWN0aW5nIHRoZSBlbmNyeXB0aW9uLCBpLmUsIDIgZW5jcnlwdGlvbnMgb2YgdGhlIHNhbWUgbWVzc2FnZSBcbi8vIHdpdGggdGhlIHNhbWUga2V5IHdpbGwgbmV2ZXIgcmVzdWx0IGludG8gdGhlIHNhbWUgZW5jcnlwdGVkIG1lc3NhZ2UuXG4vLyBcbi8vIE5vdGUgdGhhdCBmb3IgZGVjeXBoZXJpbmcsIHRoZSAqKnNhbWUqKiBpbml0aWFsaXNhdGlvbiB2ZWN0b3Igd2lsbCBiZSBuZWVkZWQuXG4vLyBUaGlzIHZlY3RvciBjYW4gc2FmZWx5IGJlIHRyYW5zZmVycmVkIGluIGNsZWFyIHdpdGggdGhlIGVuY3J5cHRlZCBtZXNzYWdlLlxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkoa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nW10+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBtZXNzYWdlVG9BcnJheUJ1ZmZlciA9IHRleHRUb0FycmF5QnVmZmVyKG1lc3NhZ2UpXG4gICAgICAgIGNvbnN0IGl2ID0gd2luZG93LmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMTIpKTtcbiAgICAgICAgY29uc3QgaXZUZXh0ID0gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhpdilcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJBRVMtR0NNXCIsIGl2IH0sXG4gICAgICAgICAgICBrZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBbYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhjeXBoZXJlZE1lc3NhZ2VBQiksIGl2VGV4dF1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIkVuY3J5cHRpb24gZmFpbGVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTeW1tZXRyaWMga2V5IG9yIG1lc3NhZ2UgdG8gZW5jcnlwdCBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLy8gRm9yIGRlY3lwaGVyaW5nLCB3ZSBuZWVkIHRoZSBrZXksIHRoZSBjeXBoZXJlZCBtZXNzYWdlIGFuZCB0aGUgaW5pdGlhbGl6YXRpb24gdmVjdG9yLiBTZWUgYWJvdmUgdGhlIFxuLy8gY29tbWVudHMgZm9yIHRoZSBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleSBmdW5jdGlvblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlY3J5cHRXaXRoU3ltbWV0cmljS2V5KGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcsIGluaXRWZWN0b3I6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZGVjb2RlZEluaXRWZWN0b3I6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihpbml0VmVjdG9yKVxuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGRlY3J5dHBlZE1lc3NhZ2VBQjogQXJyYXlCdWZmZXIgPSBhd2FpdFxuICAgICAgICAgICAgd2luZG93LmNyeXB0by5zdWJ0bGUuZGVjcnlwdChcbiAgICAgICAgICAgICAgICB7IG5hbWU6IFwiQUVTLUdDTVwiLCBpdjogZGVjb2RlZEluaXRWZWN0b3IgfSxcbiAgICAgICAgICAgICAgICBrZXksXG4gICAgICAgICAgICAgICAgYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gYXJyYXlCdWZmZXJUb1RleHQoZGVjcnl0cGVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiSW52YWxpZCBrZXksIG1lc3NhZ2Ugb3IgYWxnb3JpdGhtIGZvciBkZWNyeXB0aW9uXCIpXG4gICAgICAgIH0gZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJTeW1tZXRyaWMga2V5IG9yIG1lc3NhZ2UgdG8gZGVjcnlwdCBpcyBpbGwtZm9ybWVkXCIpXG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIkRlY3J5cHRpb24gZmFpbGVkXCIpXG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8vIFNIQS0yNTYgSGFzaCBmcm9tIGEgdGV4dFxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhc2godGV4dDogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCB0ZXh0MmFycmF5QnVmID0gdGV4dFRvQXJyYXlCdWZmZXIodGV4dClcbiAgICBjb25zdCBoYXNoZWRBcnJheSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmRpZ2VzdChcIlNIQS0yNTZcIiwgdGV4dDJhcnJheUJ1ZilcbiAgICByZXR1cm4gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhoYXNoZWRBcnJheSlcbn1cblxuY2xhc3MgS2V5U3RyaW5nQ29ycnVwdGVkIGV4dGVuZHMgRXJyb3IgeyB9XG5cbi8vIEFycmF5QnVmZmVyIHRvIGEgQmFzZTY0IHN0cmluZ1xuZnVuY3Rpb24gYXJyYXlCdWZmZXJUb0Jhc2U2NFN0cmluZyhhcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICAgIHZhciBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShhcnJheUJ1ZmZlcilcbiAgICB2YXIgYnl0ZVN0cmluZyA9ICcnXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBieXRlQXJyYXkuYnl0ZUxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGJ5dGVTdHJpbmcgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlQXJyYXlbaV0pXG4gICAgfVxuICAgIHJldHVybiBidG9hKGJ5dGVTdHJpbmcpXG59XG5cbi8vIEJhc2U2NCBzdHJpbmcgdG8gYW4gYXJyYXlCdWZmZXJcbmZ1bmN0aW9uIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoYjY0c3RyOiBzdHJpbmcpOiBBcnJheUJ1ZmZlciB7XG4gICAgdHJ5IHtcbiAgICAgICAgdmFyIGJ5dGVTdHIgPSBhdG9iKGI2NHN0cilcbiAgICAgICAgdmFyIGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZVN0ci5sZW5ndGgpXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZVN0ci5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgYnl0ZXNbaV0gPSBieXRlU3RyLmNoYXJDb2RlQXQoaSlcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gYnl0ZXMuYnVmZmVyXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhgU3RyaW5nIHN0YXJ0aW5nIGJ5ICcke2I2NHN0ci5zdWJzdHJpbmcoMCwgMTApfScgY2Fubm90IGJlIGNvbnZlcnRlZCB0byBhIHZhbGlkIGtleSBvciBtZXNzYWdlYClcbiAgICAgICAgdGhyb3cgbmV3IEtleVN0cmluZ0NvcnJ1cHRlZFxuICAgIH1cbn1cblxuLy8gU3RyaW5nIHRvIGFycmF5IGJ1ZmZlclxuZnVuY3Rpb24gdGV4dFRvQXJyYXlCdWZmZXIoc3RyOiBzdHJpbmcpOiBBcnJheUJ1ZmZlciB7XG4gICAgdmFyIGJ1ZiA9IGVuY29kZVVSSUNvbXBvbmVudChzdHIpIC8vIDIgYnl0ZXMgZm9yIGVhY2ggY2hhclxuICAgIHZhciBidWZWaWV3ID0gbmV3IFVpbnQ4QXJyYXkoYnVmLmxlbmd0aClcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ1Zi5sZW5ndGg7IGkrKykge1xuICAgICAgICBidWZWaWV3W2ldID0gYnVmLmNoYXJDb2RlQXQoaSlcbiAgICB9XG4gICAgcmV0dXJuIGJ1ZlZpZXdcbn1cblxuLy8gQXJyYXkgYnVmZmVycyB0byBzdHJpbmdcbmZ1bmN0aW9uIGFycmF5QnVmZmVyVG9UZXh0KGFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gICAgdmFyIGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKVxuICAgIHZhciBzdHIgPSAnJ1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZUFycmF5LmJ5dGVMZW5ndGg7IGkrKykge1xuICAgICAgICBzdHIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShieXRlQXJyYXlbaV0pXG4gICAgfVxuICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoc3RyKVxufVxuXG4iLCAiLy8gQWxsIG1lc3NhZ2UgdHlwZXMgYmV0d2VlbiB0aGUgYXBwbGljYXRpb24gYW5kIHRoZSBzZXJ2ZXJcbi8vIE1lc3NhZ2UgZm9yIHVzZXIgbmFtZVxuZXhwb3J0IGNsYXNzIENhc1VzZXJOYW1lIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgdXNlcm5hbWU6IHN0cmluZykgeyB9XG59XG5cblxuLy8gTWVzc2FnZSBmb3IgcmVxdWlyaW5nIGhpc3RvcnlcbmV4cG9ydCBjbGFzcyBIaXN0b3J5UmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIGFnZW50TmFtZTogc3RyaW5nLCBwdWJsaWMgaW5kZXg6IG51bWJlcikgeyB9XG59XG5cbi8vIFJlc3VsdCBvZiBoaXN0b3J5IHJlcXVlc3RcbmV4cG9ydCBjbGFzcyBIaXN0b3J5QW5zd2VyIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3VjY2VzczogYm9vbGVhbixcbiAgICAgICAgcHVibGljIGZhaWx1cmVNZXNzYWdlOiBzdHJpbmcsXG4gICAgICAgIHB1YmxpYyBpbmRleDogbnVtYmVyLFxuICAgICAgICBwdWJsaWMgYWxsTWVzc2FnZXM6IEV4dE1lc3NhZ2VbXSkgeyB9XG59XG5cbi8vIEZpbHRlcmluZyBvZiBtZXNzYWdlc1xuZXhwb3J0IGNsYXNzIEZpbHRlclJlcXVlc3Qge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBmcm9tOiBzdHJpbmcsIHB1YmxpYyB0bzogc3RyaW5nLCBwdWJsaWMgaW5kZXhtaW46IHN0cmluZykgeyB9XG59XG5cbmV4cG9ydCBjbGFzcyBGaWx0ZXJlZE1lc3NhZ2Uge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBtZXNzYWdlOiBFeHRNZXNzYWdlLFxuICAgICAgICBwdWJsaWMgaW5kZXg6IG51bWJlcixcbiAgICAgICAgcHVibGljIGRlbGV0ZWQ6IGJvb2xlYW4sXG4gICAgICAgIHB1YmxpYyBkZWxldGVyOiBzdHJpbmcpIHsgfVxufVxuXG4vLyBSZXN1bHQgb2YgZmlsdGVyaW5nIHJlcXVlc3RcbmV4cG9ydCBjbGFzcyBGaWx0ZXJpbmdBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBwdWJsaWMgZmFpbHVyZU1lc3NhZ2U6IHN0cmluZyxcbiAgICAgICAgcHVibGljIGFsbE1lc3NhZ2VzOiBGaWx0ZXJlZE1lc3NhZ2VbXSkgeyB9XG59XG5cbi8vIFNlbmRpbmcgYSBtZXNzYWdlIFJlc3VsdCBmb3JtYXRcbmV4cG9ydCBjbGFzcyBTZW5kUmVzdWx0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3VjY2VzczogYm9vbGVhbiwgcHVibGljIGVycm9yTWVzc2FnZTogc3RyaW5nKSB7IH1cbn1cblxuLy8gU2VuZGluZyBtZXNzYWdlc1xuLy8gVGhlIG1lc3NhZ2UgZm9ybWF0XG5leHBvcnQgY2xhc3MgRXh0TWVzc2FnZSB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHNlbmRlcjogc3RyaW5nLCBwdWJsaWMgcmVjZWl2ZXI6IHN0cmluZywgcHVibGljIGNvbnRlbnQ6IHN0cmluZykgeyB9XG59XG5cbmV4cG9ydCBjbGFzcyBEZWxldGluZ1JlcXVlc3Qge1xuICAgIGNvbnN0cnVjdG9yKFxuICAgICAgICBwdWJsaWMgaW5kZXhUb0RlbGV0ZTogc3RyaW5nKSB7IH1cbn1cblxuZXhwb3J0IGNsYXNzIERlbGV0aW5nQW5zd2VyIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3VjY2VzczogYm9vbGVhbixcbiAgICAgICAgbWVzc2FnZTogc3RyaW5nKSB7IH1cbn1cblxuLy8gUmVxdWVzdGluZyBrZXlzXG5leHBvcnQgY2xhc3MgS2V5UmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIG93bmVyT2ZUaGVLZXk6IHN0cmluZywgcHVibGljIHB1YmxpY0tleTogYm9vbGVhbiwgcHVibGljIGVuY3J5cHRpb246IGJvb2xlYW4pIHsgfVxufVxuXG5leHBvcnQgY2xhc3MgS2V5UmVzdWx0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3VjY2VzczogYm9vbGVhbiwgcHVibGljIGtleTogc3RyaW5nLCBwdWJsaWMgZXJyb3JNZXNzYWdlOiBzdHJpbmcpIHsgfVxufSIsICJpbXBvcnQge1xuICAgIGVuY3J5cHRXaXRoUHVibGljS2V5LCBkZWNyeXB0V2l0aFByaXZhdGVLZXksIHN0cmluZ1RvUHJpdmF0ZUtleUZvckVuY3J5cHRpb24sIHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbixcbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUsXG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUsIHByaXZhdGVLZXlUb1N0cmluZywgaGFzaCxcbiAgICBzaWduV2l0aFByaXZhdGVLZXksXG4gICAgdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleSxcbiAgICBnZW5lcmF0ZU5vbmNlXG59IGZyb20gJy4vbGliQ3J5cHRvJ1xuXG5pbXBvcnQge1xuICAgIEhpc3RvcnlBbnN3ZXIsIEhpc3RvcnlSZXF1ZXN0LCBLZXlSZXF1ZXN0LCBLZXlSZXN1bHQsIENhc1VzZXJOYW1lLCBFeHRNZXNzYWdlLCBTZW5kUmVzdWx0LFxuXG59IGZyb20gJy4vc2VydmVyTWVzc2FnZXMnXG5cbi8vIFRvIGRldGVjdCBpZiB3ZSBjYW4gdXNlIHdpbmRvdy5jcnlwdG8uc3VidGxlXG5pZiAoIXdpbmRvdy5pc1NlY3VyZUNvbnRleHQpIGFsZXJ0KFwiTm90IHNlY3VyZSBjb250ZXh0IVwiKVxuXG4vL0luZGV4IG9mIHRoZSBsYXN0IHJlYWQgbWVzc2FnZVxubGV0IGxhc3RJbmRleEluSGlzdG9yeSA9IDBcblxuY29uc3QgdXNlckJ1dHRvbkxhYmVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJ1c2VyLW5hbWVcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuY29uc3Qgc2VuZEJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwic2VuZC1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcbmNvbnN0IHJlY2VpdmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJyZWNlaXZlclwiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5jb25zdCBtZXNzYWdlID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJtZXNzYWdlXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHJlY2VpdmVkX21lc3NhZ2VzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJleGNoYW5nZWQtbWVzc2FnZXNcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuXG5mdW5jdGlvbiBjbGVhcmluZ01lc3NhZ2VzKCkge1xuICAgIHJlY2VpdmVkX21lc3NhZ2VzLnRleHRDb250ZW50ID0gXCJcIlxufVxuXG5mdW5jdGlvbiBzdHJpbmdUb0hUTUwoc3RyOiBzdHJpbmcpOiBIVE1MRGl2RWxlbWVudCB7XG4gICAgdmFyIGRpdl9lbHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKVxuICAgIGRpdl9lbHQuaW5uZXJIVE1MID0gc3RyXG4gICAgcmV0dXJuIGRpdl9lbHRcbn1cblxuZnVuY3Rpb24gYWRkaW5nUmVjZWl2ZWRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZykge1xuICAgIHJlY2VpdmVkX21lc3NhZ2VzLmFwcGVuZChzdHJpbmdUb0hUTUwoJzxwPjwvcD48cD48L3A+JyArIG1lc3NhZ2UpKVxufVxuXG4vKiBOYW1lIG9mIHRoZSB1c2VyIG9mIHRoZSBhcHBsaWNhdGlvbi4uLiBjYW4gYmUgQWxpY2UvQm9iIGZvciBhdHRhY2tpbmcgcHVycG9zZXMgKi9cbmxldCBnbG9iYWxVc2VyTmFtZSA9IFwiXCJcblxuLy8gV0FSTklORyFcbi8vIEl0IGlzIG5lY2Vzc2FyeSB0byBwYXNzIHRoZSBVUkwgcGFyYW1ldGVycywgY2FsbGVkIGB1cmxQYXJhbXNgIGJlbG93LCB0byBcbi8vIGV2ZXJ5IEdFVC9QT1NUIHF1ZXJ5IHlvdSBzZW5kIHRvIHRoZSBzZXJ2ZXIuIFRoaXMgaXMgbWFuZGF0b3J5IHRvIGhhdmUgdGhlIHBvc3NpYmlsaXR5IFxuLy8gdG8gdXNlIGFsdGVybmF0aXZlIGlkZW50aXRpZXMgbGlrZSBhbGljZUB1bml2LXJlbm5lcy5mciwgYm9iQHVuaXYtcmVubmVzLmZyLCBldGMuIFxuLy8gZm9yIGRlYnVnZ2luZyBwdXJwb3Nlcy5cbmFzeW5jIGZ1bmN0aW9uIGZldGNoQ2FzTmFtZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgY29uc3QgbmFtZXJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9nZXR1c2VyP1wiICsgdXJsUGFyYW1zLCB7XG4gICAgICAgIG1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIGlmICghbmFtZXJlcXVlc3Qub2spIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke25hbWVyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICB9XG4gICAgY29uc3QgbmFtZVJlc3VsdCA9IChhd2FpdCBuYW1lcmVxdWVzdC5qc29uKCkpIGFzIENhc1VzZXJOYW1lO1xuICAgIHJldHVybiBuYW1lUmVzdWx0LnVzZXJuYW1lXG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNldENhc05hbWUoKSB7XG4gICAgZ2xvYmFsVXNlck5hbWUgPSBhd2FpdCBmZXRjaENhc05hbWUoKVxuICAgIC8vIFdlIHJlcGxhY2UgdGhlIG5hbWUgb2YgdGhlIHVzZXIgb2YgdGhlIGFwcGxpY2F0aW9uIGFzIHRoZSBkZWZhdWx0IG5hbWVcbiAgICAvLyBJbiB0aGUgd2luZG93XG4gICAgdXNlckJ1dHRvbkxhYmVsLnRleHRDb250ZW50ID0gZ2xvYmFsVXNlck5hbWVcbiAgICBsb2FkTm9uY2VzKCkgLy91dGlsaXNhdGlvbiBkZSBsb2FkTm9uY2VzKCkgcG91ciByZXN0YXVyZXIgbGUgdGFibGVhdSBldCBhaW5zaSB2XHUwMEU5cmlmaWVyIGxlcyBub25jZXMgcXVpIHRyYW5zaXRlbnQgYXByZXMgcmVjb25uZXhpb25cbn1cblxuc2V0Q2FzTmFtZSgpXG5cbi8qIE5hbWUgb2YgdGhlIG93bmVyL2RldmVsb3BwZXIgb2YgdGhlIGFwcGxpY2F0aW9uLCBpLmUsIHRoZSBuYW1lIG9mIHRoZSBmb2xkZXIgXG4gICB3aGVyZSB0aGUgd2ViIHBhZ2Ugb2YgdGhlIGFwcGxpY2F0aW9uIGlzIHN0b3JlZC4gRS5nLCBmb3IgdGVhY2hlcnMnIGFwcGxpY2F0aW9uXG4gICB0aGlzIG5hbWUgaXMgXCJlbnNcIiAqL1xuXG5mdW5jdGlvbiBnZXRPd25lck5hbWUoKTogc3RyaW5nIHtcbiAgICBjb25zdCBwYXRoID0gd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lXG4gICAgY29uc3QgbmFtZSA9IHBhdGguc3BsaXQoXCIvXCIsIDIpWzFdXG4gICAgcmV0dXJuIG5hbWVcbn1cblxubGV0IG93bmVyTmFtZSA9IGdldE93bmVyTmFtZSgpXG5cblxuY29uc3Qga2V5Q2FjaGUgOiB7W2tleTpzdHJpbmddIDogQ3J5cHRvS2V5fSA9IHt9IC8vdGFibGVhdSBwb3VyIHN0b2NrZXIgbGVzIGNsXHUwMEU5cyBwb3VyIFx1MDBFOXZpdGVyIGRlIGxlcyByZWRlbWFuZFx1MDBFOXMgXHUwMEUwIGNoYXF1ZSBmb2lzXG5cbmFzeW5jIGZ1bmN0aW9uIGZldGNoS2V5KHVzZXI6IHN0cmluZywgcHVibGljS2V5OiBib29sZWFuLCBlbmNyeXB0aW9uOiBib29sZWFuKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICAvLyBNaXNlIGVuIGNhY2hlIGxvY2FsZSBwb3VyIFx1MDBFOXZpdGVyIGRlIHJlZGVtYW5kZXIgbGEgY2xcdTAwRTkgXHUwMEUwIGNoYXF1ZSBhcHBlbFxuICAgIGNvbnN0IGtleUlkID0gYCR7dXNlcn0tJHtwdWJsaWNLZXkgPyAncHViJyA6ICdwcml2J30tJHtlbmNyeXB0aW9uID8gJ2VuYycgOiAnc2lnJ31gXG4gICAgXG4gICAgaWYgKGtleUNhY2hlW2tleUlkXSkge1xuICAgICAgICByZXR1cm4ga2V5Q2FjaGVba2V5SWRdXG4gICAgfVxuXG4gICAgY29uc3Qga2V5UmVxdWVzdE1lc3NhZ2UgPSBuZXcgS2V5UmVxdWVzdCh1c2VyLCBwdWJsaWNLZXksIGVuY3J5cHRpb24pXG4gICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKVxuXG4gICAgY29uc3Qga2V5cmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL2dldEtleT9cIiArIHVybFBhcmFtcywge1xuICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShrZXlSZXF1ZXN0TWVzc2FnZSksXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgIGlmICgha2V5cmVxdWVzdC5vaykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7a2V5cmVxdWVzdC5zdGF0dXN9YCk7XG4gICAgfVxuXG4gICAgY29uc3Qga2V5UmVzdWx0ID0gKGF3YWl0IGtleXJlcXVlc3QuanNvbigpKSBhcyBLZXlSZXN1bHRcbiAgICBpZiAoIWtleVJlc3VsdC5zdWNjZXNzKSB0aHJvdyBuZXcgRXJyb3Ioa2V5UmVzdWx0LmVycm9yTWVzc2FnZSlcblxuICAgIGxldCBrZXk6IENyeXB0b0tleVxuICAgIGlmIChwdWJsaWNLZXkgJiYgZW5jcnlwdGlvbikga2V5ID0gYXdhaXQgc3RyaW5nVG9QdWJsaWNLZXlGb3JFbmNyeXB0aW9uKGtleVJlc3VsdC5rZXkpXG4gICAgZWxzZSBpZiAoIXB1YmxpY0tleSAmJiBlbmNyeXB0aW9uKSBrZXkgPSBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKGtleVJlc3VsdC5rZXkpXG4gICAgZWxzZSBpZiAocHVibGljS2V5ICYmICFlbmNyeXB0aW9uKSBrZXkgPSBhd2FpdCBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShrZXlSZXN1bHQua2V5KVxuICAgIGVsc2Uga2V5ID0gYXdhaXQgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKGtleVJlc3VsdC5rZXkpXG5cbiAgICBrZXlDYWNoZVtrZXlJZF0gPSBrZXlcbiAgICByZXR1cm4ga2V5XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNlbmRNZXNzYWdlKGFnZW50TmFtZTogc3RyaW5nLCByZWNlaXZlck5hbWU6IHN0cmluZywgbWVzc2FnZUNvbnRlbnQ6IHN0cmluZyk6IFByb21pc2U8U2VuZFJlc3VsdD4ge1xuICAgIHRyeSB7XG4gICAgICAgIGxldCBtZXNzYWdlVG9TZW5kID1cbiAgICAgICAgICAgIG5ldyBFeHRNZXNzYWdlKGFnZW50TmFtZSwgcmVjZWl2ZXJOYW1lLCBtZXNzYWdlQ29udGVudClcbiAgICAgICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcblxuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvc2VuZGluZ01lc3NhZ2UvXCIgKyBvd25lck5hbWUgKyBcIj9cIiArIHVybFBhcmFtcywge1xuICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KG1lc3NhZ2VUb1NlbmQpLFxuICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBEZWFsaW5nIHdpdGggdGhlIGFuc3dlciBvZiB0aGUgbWVzc2FnZSBzZXJ2ZXJcbiAgICAgICAgcmV0dXJuIChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgU2VuZFJlc3VsdFxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCdlcnJvciBtZXNzYWdlOiAnLCBlcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2VuZFJlc3VsdChmYWxzZSwgZXJyb3IubWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlbmRSZXN1bHQoZmFsc2UsICdBbiB1bmV4cGVjdGVkIGVycm9yIG9jY3VycmVkJylcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLy8gZnVuY3Rpb24gZm9yIHJlZnJlc2hpbmcgdGhlIGNvbnRlbnQgb2YgdGhlIHdpbmRvdyAoYXV0b21hdGljIG9yIG1hbnVhbCBzZWUgYmVsb3cpXG5hc3luYyBmdW5jdGlvbiByZWZyZXNoKCkge1xuXG4gICAgLy9Qcm9wcmlcdTAwRTl0XHUwMEU5IDQgOiBUb2xcdTAwRTlyYW5jZSBcdTAwRTAgbFx1MjAxOWFzeW5jaHJvbmlzbWVcbiAgICAvLyBDZXR0ZSBmb25jdGlvbiBwZXJtZXQgXHUwMEUwIHVuIHV0aWxpc2F0ZXVyIGRlIHJcdTAwRTljdXBcdTAwRTlyZXIgZGVzIG1lc3NhZ2VzIG1cdTAwRUFtZSBzXHUyMDE5aWwgXHUwMEU5dGFpdCBkXHUwMEU5Y29ubmVjdFx1MDBFOVxuXG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgdXNlciA9IGdsb2JhbFVzZXJOYW1lXG4gICAgICAgIGNvbnN0IGhpc3RvcnlSZXF1ZXN0ID1cbiAgICAgICAgICAgIG5ldyBIaXN0b3J5UmVxdWVzdCh1c2VyLCBsYXN0SW5kZXhJbkhpc3RvcnkpXG4gICAgICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgICAgIGNvbnN0IHJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9oaXN0b3J5L1wiICsgb3duZXJOYW1lICsgXCI/XCIgKyB1cmxQYXJhbXNcbiAgICAgICAgICAgICwge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoaGlzdG9yeVJlcXVlc3QpLFxuICAgICAgICAgICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgaWYgKCFyZXF1ZXN0Lm9rKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7cmVxdWVzdC5zdGF0dXN9IGApO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgSGlzdG9yeUFuc3dlclxuICAgICAgICBpZiAoIXJlc3VsdC5zdWNjZXNzKSB7IGFsZXJ0KHJlc3VsdC5mYWlsdXJlTWVzc2FnZSkgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGxhc3RJbmRleEluSGlzdG9yeSA9IHJlc3VsdC5pbmRleFxuICAgICAgICAgICAgZm9yIChjb25zdCBtIG9mIHJlc3VsdC5hbGxNZXNzYWdlcykge1xuICAgICAgICAgICAgICAgIGNvbnN0IFtpc1ZhbGlkLCBzZW5kZXIsIGNsZWFyTWVzc2FnZV0gPSBhd2FpdCBhbmFseXNlTWVzc2FnZShtKVxuICAgICAgICAgICAgICAgIGlmIChpc1ZhbGlkKSB7XG4gICAgICAgICAgICAgICAgICAgIGFkZGluZ1JlY2VpdmVkTWVzc2FnZShgJHtzZW5kZXJ9IC0+ICR7dXNlcn0gOiAke2NsZWFyTWVzc2FnZX1gKVxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiTWVzc2FnZSBpbnZhbGlkZSBvdSBub24gZFx1MDBFOWNoaWZmcmFibGVcIilcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZXJyb3IgbWVzc2FnZTogJywgZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm4gZXJyb3IubWVzc2FnZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnO1xuICAgICAgICB9XG4gICAgfVxufVxuXG4vLyBBdXRvbWF0aWMgcmVmcmVzaFxuY29uc3QgaW50ZXJ2YWxSZWZyZXNoID0gc2V0SW50ZXJ2YWwocmVmcmVzaCwgMjAwMClcblxuLy9UYWJsZWF1IGRlIG5vbmNlIHV0aWxpc1x1MDBFOSBwb3VyIHZcdTAwRTlyaWZpZXIgbGVzIEFDSyAoUHJvcHJpXHUwMEU5dFx1MDBFOSAzKVxuY29uc3QgdmVyaWZOb25jZToge1xuICAgIFtub25jZTogc3RyaW5nXTogeyByZWNlaXZlcjogc3RyaW5nLCBtZXNzYWdlOiBzdHJpbmcgfVxufSA9IHt9XG5cbi8vIGZvbmN0aW9uIHBvdXIgc3RvY2tlciBsZXMgbm9uY2VzIGRhbnMgdW4gdGFibGVhdSAoUHJvcHJpXHUwMEU5dFx1MDBFOSA1KVxuZnVuY3Rpb24gc2F2ZU5vbmNlcygpIHtcbiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShcIm5vbmNlc1wiLCBKU09OLnN0cmluZ2lmeSh2ZXJpZk5vbmNlKSlcbn1cblxuLy9mb25jdGlvbiBwb3VyIG1ldHRyZSBsZXMgbm9uY2VzIGR1IHRhYmxlYXUgdmVyaWZOb25jZSBkYW5zIGxlIGxvY2FsU3RvcmFnZSAoUHJvcHJpXHUwMEU5dFx1MDBFOSA1KVxuZnVuY3Rpb24gbG9hZE5vbmNlcygpIHtcbiAgICBjb25zdCBzdG9yZWQgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShcIm5vbmNlc1wiKVxuICAgIGlmIChzdG9yZWQpIE9iamVjdC5hc3NpZ24odmVyaWZOb25jZSwgSlNPTi5wYXJzZShzdG9yZWQpKVxufVxuXG5zZW5kQnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgY29uc3QgYWdlbnROYW1lID0gZ2xvYmFsVXNlck5hbWVcbiAgICBjb25zdCByZWNlaXZlck5hbWUgPSByZWNlaXZlci52YWx1ZS50cmltKClcbiAgICBjb25zdCBtc2cgPSBtZXNzYWdlLnZhbHVlLnRyaW0oKVxuXG4gICAgaWYgKHJlY2VpdmVyTmFtZSA9PT0gXCJcIiB8fCBtc2cgPT09IFwiXCIpIHtcbiAgICAgICAgYWxlcnQoXCJWZXVpbGxleiByZW1wbGlyIHRvdXMgbGVzIGNoYW1wcy5cIilcbiAgICAgICAgcmV0dXJuXG4gICAgfVxuXG4gICAgdHJ5IHtcbiAgICAgICAgIC8vIFByb3ByaVx1MDBFOXRcdTAwRTkgMyA6IE5vbmNlIHVuaXF1ZSBwb3VyIGxcdTIwMTlBQ0tcbiAgICAgICAgY29uc3Qgbm9uY2UgPSBnZW5lcmF0ZU5vbmNlKClcbiAgICAgICAgdmVyaWZOb25jZVtub25jZV0gPSB7XG4gICAgICAgICAgICByZWNlaXZlcjogcmVjZWl2ZXJOYW1lLFxuICAgICAgICAgICAgbWVzc2FnZTogbXNnXG4gICAgICAgIH1cblxuICAgICAgICBzYXZlTm9uY2VzKCkgLy8gYXByXHUwMEU4cyBjclx1MDBFOWF0aW9uIG9uIHNhdXZlZ2FyZGUgbGUgbm9uY2UgXG5cblxuICAgICAgICAvLyBDclx1MDBFOWF0aW9uIGR1IGNvbnRlbnUgY2xhaXIgZHUgbWVzc2FnZSBcdTAwRTAgY2hpZmZyZXJcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IHtcbiAgICAgICAgICAgIG1zZyxcbiAgICAgICAgICAgIG5vbmNlXG4gICAgICAgIH1cbiAgICAgIFxuICAgICAgICAvL2ljaSBvbiBhIGRcdTAwRTljaWRcdTAwRTkgZGUgcmVzcGVjdGVyIGxlIHByb3RvY29sZSBzdWl2YW50IEEgXHUyMTkyIEIgOiBBLCB7IHsgbSwgTmEgfXBrKEIpIH1zayhBKSBcbiAgICAgICAgLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEIgXHUyMTkyIEEgOiBCLCB7IE5hIH1wayhBKVxuXG4gICAgICAgIC8vIFByb3ByaVx1MDBFOXRcdTAwRTkgMSA6IENvbmZpZGVudGlhbGl0XHUwMEU5IC0gY2hpZmZyZW1lbnQgYXZlYyBsYSBjbFx1MDBFOSBwdWJsaXF1ZSBkdSBkZXN0aW5hdGFpcmVcblxuICAgICAgICBjb25zdCByZWNlaXZlclB1YmxpY0tleSA9IGF3YWl0IGZldGNoS2V5KHJlY2VpdmVyTmFtZSwgdHJ1ZSwgdHJ1ZSlcbiAgICAgICAgY29uc3QgZW5jcnlwdGVkTWVzc2FnZSA9IGF3YWl0IGVuY3J5cHRXaXRoUHVibGljS2V5KHJlY2VpdmVyUHVibGljS2V5LCBKU09OLnN0cmluZ2lmeShwYXlsb2FkKSlcblxuICAgICAgICAvLyBQcm9wcmlcdTAwRTl0XHUwMEU5IDIgOiBBdXRoZW50aWZpY2F0aW9uIC0gc2lnbmF0dXJlIGF2ZWMgbGEgY2xcdTAwRTkgcHJpdlx1MDBFOWUgZGUgbFx1MjAxOWV4cFx1MDBFOWRpdGV1clxuXG4gICAgICAgIGNvbnN0IHNpZ25NZXNzYWdlID0gYXdhaXQgZmV0Y2hLZXkoYWdlbnROYW1lLCBmYWxzZSwgZmFsc2UpXG4gICAgICAgIGNvbnN0IE1lc3NTaWduID0gYXdhaXQgc2lnbldpdGhQcml2YXRlS2V5KHNpZ25NZXNzYWdlLCBlbmNyeXB0ZWRNZXNzYWdlKVxuXG4gICAgICAgIC8vIEVudmVsb3BwZSBmaW5hbGUgXHUwMEUwIGVudm95ZXIuIE9uIHV0aWxpc2UgSlNPTi5zdHJpbmdpZnkoLi4uKSBwb3VyIHRyYW5zZm9ybWVyIGNldCBvYmpldCBlbiB1bmUgKipjaGFcdTAwRUVuZSBkZSBjYXJhY3RcdTAwRThyZXMqKiBhdSBmb3JtYXQgSlNPTixcbiAgICAgICAgLy8gYWZpbiBkZSBsJ2Vudm95ZXIgY29tbWUgYHN0cmluZ2AgZGFucyBsYSByZXF1XHUwMEVBdGUgSFRUUC5cbiAgICAgICAgY29uc3Qgc2lnbmV0TWVzcyA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICAgIGVuY3J5cHRlZDogZW5jcnlwdGVkTWVzc2FnZSxcbiAgICAgICAgICAgIHNpZ25hdHVyZTogTWVzc1NpZ25cbiAgICAgICAgfSlcblxuXG4gICAgICAgIC8vIGVudm9pZSBkdSBtZXNzYWdlIFxuICAgICAgICBjb25zdCBzZW5kUmVzdWx0ID0gYXdhaXQgc2VuZE1lc3NhZ2UoYWdlbnROYW1lLCByZWNlaXZlck5hbWUsIHNpZ25ldE1lc3MpXG5cblxuICAgICAgICAvLyB1biB0ZXN0IHBvdXIgYWZmaWNoZXIgdW5lIHBvc3NpYmxlIGVycmV1ciBkJ2Vudm9pZSBzaW5vbiBsJ2FmZmljaGFnZSBkdSBtZXNzYWdlXG4gICAgICAgIGlmICghc2VuZFJlc3VsdC5zdWNjZXNzKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhzZW5kUmVzdWx0LmVycm9yTWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiTWVzc2FnZSBlbnZveVx1MDBFOSBhdmVjIHN1Y2NcdTAwRThzXCIpXG4gICAgICAgICAgICBjb25zdCB0aW1lID0gcmVhZGFibGVUaW1lKClcbiAgICAgICAgICAgIGNvbnN0IHRleHRUb0FkZCA9IGA8Zm9udCBjb2xvcj1cImJsdWVcIj4gJHthZ2VudE5hbWV9IC0+ICR7cmVjZWl2ZXJOYW1lfSA6ICgke3RpbWV9KSAke21zZ30gPC9mb250PmBcbiAgICAgICAgICAgIGFkZGluZ1JlY2VpdmVkTWVzc2FnZSh0ZXh0VG9BZGQpXG4gICAgICAgICAgICBtZXNzYWdlLnZhbHVlID0gXCJcIlxuICAgICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZXJyb3IgbWVzc2FnZTogJywgZS5tZXNzYWdlKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc29sZS5sb2coJ3VuZXhwZWN0ZWQgZXJyb3I6ICcsIGUpXG4gICAgICAgIH1cbiAgICB9XG59XG5cblxuXG5cblxuLy8gUmV0dXJuaW5nIGEgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgY3VycmVudCB0aW1lIGluIHRoZSBmb3JtYXRcbi8vIEhIOk1NOlNTXG5mdW5jdGlvbiByZWFkYWJsZVRpbWUoKTogc3RyaW5nIHtcbiAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpXG4gICAgY29uc3QgaG91cnMgPSBub3cuZ2V0SG91cnMoKS50b1N0cmluZygpXG4gICAgY29uc3QgbWludXRlcyA9IG5vdy5nZXRNaW51dGVzKCkudG9TdHJpbmcoKVxuICAgIGNvbnN0IHNlY29uZHMgPSBub3cuZ2V0U2Vjb25kcygpLnRvU3RyaW5nKClcbiAgICAvLyBTaW5jZSBnZXRIb3VycygpIGV0YyByZXR1cm4gYSBkZWNpbWFsIGNvdW50IGZvciBob3VycywgZXRjLiB3ZSBleHBsaWNpdGVseSBhZGQgMCB3aGVuIHRoZXJlXG4gICAgLy8gYXJlIG5vIHRlbnMgZGlnaXQuXG4gICAgcmV0dXJuIGAkeyhob3Vycy5sZW5ndGggPT09IDEpID8gXCIwXCIgKyBob3VycyA6IGhvdXJzfTokeyhtaW51dGVzLmxlbmd0aCA9PT0gMSkgPyBcIjBcIiArIG1pbnV0ZXMgOiBtaW51dGVzfTokeyhzZWNvbmRzLmxlbmd0aCA9PT0gMSkgPyBcIjBcIiArIHNlY29uZHMgOiBzZWNvbmRzfWBcbn1cblxuXG5hc3luYyBmdW5jdGlvbiBhbmFseXNlTWVzc2FnZShtZXNzYWdlOiBFeHRNZXNzYWdlKTogUHJvbWlzZTxbYm9vbGVhbiwgc3RyaW5nLCBzdHJpbmddPiB7XG4gICAgY29uc3QgdXNlciA9IGdsb2JhbFVzZXJOYW1lXG4gICAgY29uc3Qgc2VuZGVyID0gbWVzc2FnZS5zZW5kZXJcbiAgICBjb25zdCBjb250ZW50ID0gbWVzc2FnZS5jb250ZW50XG5cbiAgICAvL2VycmV1ciBzaSBsZSBtZXNzYWdlIG4nZXN0IHBhcyBkZXN0aW5cdTAwRTkgXHUwMEUwIGwndXRpbGlzYXRldXIgYWN0dWVsbGVtZW50IGNvbm5lY3RcdTAwRTksIGFsb3JzIG9uIGwnaWdub3JlLlxuICAgIGlmIChtZXNzYWdlLnJlY2VpdmVyICE9PSB1c2VyKSByZXR1cm4gW2ZhbHNlLCBcIlwiLCBcIlwiXVxuXG4gICAgLy8gQ2FzIDEgOiBjXHUyMDE5ZXN0IHVuIG1lc3NhZ2UgQUNLIFx1MjE5MiB7IGVuY3J5cHRlZCB9IHNhbnMgc2lnbmF0dXJlXG4gICAgdHJ5IHtcblxuICAgICAgICAvL29uIGRcdTAwRTljb2RlIGxlIG1lc3NhZ2UgcmVcdTAwRTd1IFxuICAgICAgICBjb25zdCBwYXJzZWRBY2sgPSBKU09OLnBhcnNlKGNvbnRlbnQpXG4gICAgICAgIFxuICAgICAgICAvL3NpIGRhbnMgbGUgY29udGVudCBpbCB5IGEgdW4gZW5jcnlwdGVkIGV0IHBhcyBkZSBzaWduYXR1cmVcbiAgICAgICAgaWYgKHBhcnNlZEFjay5lbmNyeXB0ZWQgJiYgIXBhcnNlZEFjay5zaWduYXR1cmUpIHtcbiAgICAgICAgICAgIC8vb24gcmVjdXBcdTAwRThyZSBsZSBjb250ZW51IGR1IG1lc3NhZ2UgY2hpZmZyXHUwMEU5XG4gICAgICAgICAgICBjb25zdCBlbmNyeXB0ZWRBY2sgPSBwYXJzZWRBY2suZW5jcnlwdGVkXG4gICAgICAgICAgICAvL29uIHJcdTAwRTljdXBcdTAwRThyZSBsYSBjbFx1MDBFOSBwcml2XHUwMEU5ZSBwb3VyIGRcdTAwRTljaGlmZnJcdTAwRTlcbiAgICAgICAgICAgIGNvbnN0IHByaXZhdGVLZXkgPSBhd2FpdCBmZXRjaEtleSh1c2VyLCBmYWxzZSwgdHJ1ZSlcbiAgICAgICAgICAgIC8vb24gbCd1dGlsaXNlIHBvdXIgZFx1MDBFOWNoaWZmclx1MDBFOSBsZSBtZXNzYWdlXG4gICAgICAgICAgICBjb25zdCBkZWNyeXB0ZWROb25jZSA9IGF3YWl0IGRlY3J5cHRXaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5LCBlbmNyeXB0ZWRBY2spXG5cblxuICAgICAgICAgICAgLy9hdmVjIGxlIGNoYW1wIGRlY3J5cHRlZE5vbmNlIHF1aSBjb3JyZXNwb25kIGF1IG5vbmNlIHJlbnZveVx1MDBFOSBvbiB2XHUwMEU5cmlmaWUgcXUnaWwgZXN0IGRhbnMgbGUgdGFibGVhdVxuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSB2ZXJpZk5vbmNlW2RlY3J5cHRlZE5vbmNlXVxuXG4gICAgICAgICAgICAvLyBTaSBvbiB0cm91dmUgdW5lIGVudHJcdTAwRTllIGRhbnMgbGEgdGFibGUgYHZlcmlmTm9uY2VgIHBvdXIgY2Ugbm9uY2UsXG4gICAgICAgICAgICAvLyBldCBxdWUgbGUgbWVzc2FnZSBBQ0sgcHJvdmllbnQgYmllbiBkdSBkZXN0aW5hdGFpcmUgcHJcdTAwRTl2dSAoYHNlbmRlcmApLFxuICAgICAgICAgICAgLy8gYWxvcnMgbCdhY2N1c1x1MDBFOSBkZSByXHUwMEU5Y2VwdGlvbiBlc3QgY29uc2lkXHUwMEU5clx1MDBFOSBjb21tZSB2YWxpZGUuXG5cbiAgICAgICAgICAgIGlmIChleHBlY3RlZCAmJiBleHBlY3RlZC5yZWNlaXZlciA9PT0gc2VuZGVyKSB7XG4gICAgICAgICAgICAgICAgIC8vIE9uIHN1cHByaW1lIGxlIG5vbmNlIGR1IHRhYmxlYXUgY2FyIG9uIGEgcmVcdTAwRTd1IGwnYWNjdXNcdTAwRTkgdW5lIHNldWxlIGZvaXNcbiAgICAgICAgICAgICAgICBkZWxldGUgdmVyaWZOb25jZVtkZWNyeXB0ZWROb25jZV1cbiAgICAgICAgICAgICAgICAvLyBPbiBzYXV2ZWdhcmRlIGxhIHRhYmxlIG1pc2UgXHUwMEUwIGpvdXIgZGFucyBsZSBsb2NhbFN0b3JhZ2UgcG91ciBsYSBwZXJzaXN0YW5jZVxuICAgICAgICAgICAgICAgIHNhdmVOb25jZXMoKVxuICAgICAgICAgICAgICAgICAvLyBPbiBhZmZpY2hlIHVuIG1lc3NhZ2UgaW5kaXF1YW50IHF1ZSBsZSBkZXN0aW5hdGFpcmUgYSBiaWVuIHJlXHUwMEU3dSBub3RyZSBtZXNzYWdlXG4gICAgICAgICAgICAgICAgcmV0dXJuIFt0cnVlLCBzZW5kZXIsIGAke3JlYWRhYmxlVGltZSgpfSAtIGxlIG1lc3NhZ2UgYSBcdTAwRTl0XHUwMEU5IGVudm95XHUwMEU5IGV0IHJlXHUwMEU3dSBcdTAwRTAgJHtyZWFkYWJsZVRpbWUoKX1gXVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcIkFDSyByZVx1MDBFN3UgYXZlYyBub25jZSBpbmNvbm51IDpcIiwgZGVjcnlwdGVkTm9uY2UpXG4gICAgICAgICAgICAgICAgcmV0dXJuIFtmYWxzZSwgXCJcIiwgXCJcIl1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgLy8gUGFzIHVuIEFDSyBvdSBKU09OIG1hbCBmb3JtXHUwMEU5IDogb24gdGVudGUgbGUgbWVzc2FnZSBzdGFuZGFyZFxuICAgIH1cblxuICAgIC8vIENhcyAyIDogbWVzc2FnZSBub3JtYWwgc2lnblx1MDBFOSBcdTIxOTIgeyBlbmNyeXB0ZWQsIHNpZ25hdHVyZSB9XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcGFyc2VkTXNnID0gSlNPTi5wYXJzZShjb250ZW50KVxuICAgICAgICBjb25zdCB7IGVuY3J5cHRlZCwgc2lnbmF0dXJlIH0gPSBwYXJzZWRNc2dcblxuICAgICAgICBpZiAoIWVuY3J5cHRlZCB8fCAhc2lnbmF0dXJlKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIk1lc3NhZ2UgbWFsIGZvcm1cdTAwRTkgKG1hbnF1ZSBlbmNyeXB0ZWQgb3Ugc2lnbmF0dXJlKVwiKVxuICAgICAgICAgICAgcmV0dXJuIFtmYWxzZSwgXCJcIiwgXCJcIl1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFZcdTAwRTlyaWZpZSBzaWduYXR1cmVcbiAgICAgICAgY29uc3Qgc2VuZGVyUHViS2V5ID0gYXdhaXQgZmV0Y2hLZXkoc2VuZGVyLCB0cnVlLCBmYWxzZSlcbiAgICAgICAgY29uc3QgdmFsaWQgPSBhd2FpdCB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KHNlbmRlclB1YktleSwgZW5jcnlwdGVkLCBzaWduYXR1cmUpXG4gICAgICAgIGlmICghdmFsaWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU2lnbmF0dXJlIG5vbiB2YWxpZGVcIilcbiAgICAgICAgICAgIHJldHVybiBbZmFsc2UsIFwiXCIsIFwiXCJdXG4gICAgICAgIH1cblxuICAgICAgICAvLyBEXHUwMEU5Y2hpZmZyZVxuICAgICAgICBjb25zdCBwcml2YXRlS2V5ID0gYXdhaXQgZmV0Y2hLZXkodXNlciwgZmFsc2UsIHRydWUpXG4gICAgICAgIGNvbnN0IGRlY3J5cHRlZCA9IGF3YWl0IGRlY3J5cHRXaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5LCBlbmNyeXB0ZWQpXG5cbiAgICAgICAgLy8gTWFpbnRlbmFudCBxdVx1MjAxOW9uIGEgbGUgY2xhaXIsIG9uIHBldXQgcGFyc2VyXG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnBhcnNlKGRlY3J5cHRlZClcbiAgICAgICAgY29uc3QgbXNnID0gcGF5bG9hZC5tc2dcbiAgICAgICAgY29uc3Qgbm9uY2UgPSBwYXlsb2FkLm5vbmNlXG5cbiAgICAgICAgaWYgKCFtc2cgfHwgIW5vbmNlKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlBheWxvYWQgaW5jb21wbGV0IDpcIiwgcGF5bG9hZClcbiAgICAgICAgICAgIHJldHVybiBbZmFsc2UsIFwiXCIsIFwiXCJdXG4gICAgICAgIH1cblxuICAgICAgICAvLyBFbnZvaWUgQUNLXG4gICAgICAgIGF3YWl0IHNlbmRBY2tub3dsZWRnbWVudCh1c2VyLCBzZW5kZXIsIG5vbmNlKVxuXG4gICAgICAgIHJldHVybiBbdHJ1ZSwgc2VuZGVyLCBgJHtyZWFkYWJsZVRpbWUoKX0gLSAke21zZ31gXVxuXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjb25zb2xlLmVycm9yKFwiRXJyZXVyIGRhbnMgYW5hbHlzZU1lc3NhZ2UgOlwiLCBlKVxuICAgICAgICByZXR1cm4gW2ZhbHNlLCBcIlwiLCBcIlwiXVxuICAgIH1cbn1cblxuXG5cblxuLy8gZW52b2llIHVuIEFDSyBhdSBkZXN0aW5hdGFpcmUgZCdvcmlnaW5lIGR1IG1lc3NhZ2UgKGxlIHNlbmRlcikuXG5cbmFzeW5jIGZ1bmN0aW9uIHNlbmRBY2tub3dsZWRnbWVudChyZWNlaXZlcjogc3RyaW5nLCBzZW5kZXI6IHN0cmluZywgbm9uY2U6IHN0cmluZykge1xuICAgIHRyeSB7XG4gICAgICAgIC8vIE9uIGNoaWZmcmUgdW5pcXVlbWVudCBsZSBub25jZSBicnV0IChwYXMgZGUgSlNPTilcbiAgICAgICAgY29uc3Qgc2VuZGVyUHVibGljS2V5ID0gYXdhaXQgZmV0Y2hLZXkoc2VuZGVyLCB0cnVlLCB0cnVlKVxuXG4gICAgICAgIC8vIE9uIGNoaWZmcmUgbGUgbm9uY2UgYnJ1dCBhdmVjIGxhIGNsXHUwMEU5IHB1YmxpcXVlIGR1IGRlc3RpbmF0YWlyZSBkdSBBQ0tcbiAgICAgICAgLy8gQ2VsYSBnYXJhbnRpdCBxdWUgc2V1bCBgc2VuZGVyYCBwb3VycmEgZFx1MDBFOWNoaWZmcmVyIGNlIG1lc3NhZ2UuICAgXG4gICAgICAgIGNvbnN0IGVuY3J5cHRlZEFjayA9IGF3YWl0IGVuY3J5cHRXaXRoUHVibGljS2V5KHNlbmRlclB1YmxpY0tleSwgbm9uY2UpXG5cbiAgICAgICAgY29uc3QgYWNrTWVzc2FnZSA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICAgIGVuY3J5cHRlZDogZW5jcnlwdGVkQWNrXG4gICAgICAgIH0pXG5cbiAgICAgICAgLy8gT24gZW52b2llIGNlIG1lc3NhZ2UgY2hpZmZyXHUwMEU5IGRlIGByZWNlaXZlcmAgKGNlbHVpIHF1aSBhIHJlXHUwMEU3dSBsZSBtZXNzYWdlIG9yaWdpbmFsKSB2ZXJzIGBzZW5kZXJgIChjZWx1aSBxdWkgYSBlbnZveVx1MDBFOSBsZSBtZXNzYWdlKVxuICAgICAgICBjb25zdCBzZW5kUmVzdWx0ID0gYXdhaXQgc2VuZE1lc3NhZ2UocmVjZWl2ZXIsIHNlbmRlciwgYWNrTWVzc2FnZSlcblxuICAgICAgICBpZiAoIXNlbmRSZXN1bHQuc3VjY2Vzcykge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCIgXHUwMEM5Y2hlYyBkZSBsJ2Vudm9pIGR1IEFDSyA6XCIsIHNlbmRSZXN1bHQuZXJyb3JNZXNzYWdlKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCIgQUNLIGVudm95XHUwMEU5IFx1MDBFMFwiLCBzZW5kZXIpXG4gICAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoXCJFcnJldXIgZGFucyBzZW5kQWNrbm93bGVkZ21lbnQgOlwiLCBlKVxuICAgIH1cbn1cblxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQTBDQSxlQUFzQiwrQkFBK0IsWUFBd0M7QUFDekYsTUFBSTtBQUNBLFVBQU0saUJBQThCLDBCQUEwQixVQUFVO0FBQ3hFLFVBQU0sTUFBaUIsTUFBTSxPQUFPLE9BQU8sT0FBTztBQUFBLE1BQzlDO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxRQUNJLE1BQU07QUFBQSxRQUNOLE1BQU07QUFBQSxNQUNWO0FBQUEsTUFDQTtBQUFBLE1BQ0EsQ0FBQyxTQUFTO0FBQUEsSUFDZDtBQUNBLFdBQU87QUFBQSxFQUNYLFNBQVMsR0FBRztBQUNSLFFBQUksYUFBYSxjQUFjO0FBQUUsY0FBUSxJQUFJLDJE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LFVBQVUsSUFBSTtBQUVqQyxRQUFJLENBQUMsYUFBYSxDQUFDLFdBQVc7QUFDMUIsY0FBUSxJQUFJLHNEQUFtRDtBQUMvRCxhQUFPLENBQUMsT0FBTyxJQUFJLEVBQUU7QUFBQSxJQUN6QjtBQUdBLFVBQU0sZUFBZSxNQUFNLFNBQVMsUUFBUSxNQUFNLEtBQUs7QUFDdkQsVUFBTSxRQUFRLE1BQU0sNkJBQTZCLGNBQWMsV0FBVyxTQUFTO0FBQ25GLFFBQUksQ0FBQyxPQUFPO0FBQ1IsY0FBUSxJQUFJLHNCQUFzQjtBQUNsQyxhQUFPLENBQUMsT0FBTyxJQUFJLEVBQUU7QUFBQSxJQUN6QjtBQUdBLFVBQU0sYUFBYSxNQUFNLFNBQVMsTUFBTSxPQUFPLElBQUk7QUFDbkQsVUFBTSxZQUFZLE1BQU0sc0JBQXNCLFlBQVksU0FBUztBQUduRSxVQUFNLFVBQVUsS0FBSyxNQUFNLFNBQVM7QUFDcEMsVUFBTSxNQUFNLFFBQVE7QUFDcEIsVUFBTSxRQUFRLFFBQVE7QUFFdEIsUUFBSSxDQUFDLE9BQU8sQ0FBQyxPQUFPO0FBQ2hCLGNBQVEsSUFBSSx1QkFBdUIsT0FBTztBQUMxQyxhQUFPLENBQUMsT0FBTyxJQUFJLEVBQUU7QUFBQSxJQUN6QjtBQUdBLFVBQU0sbUJBQW1CLE1BQU0sUUFBUSxLQUFLO0FBRTVDLFdBQU8sQ0FBQyxNQUFNLFFBQVEsR0FBRyxhQUFhLENBQUMsTUFBTSxHQUFHLEVBQUU7QUFBQSxFQUV0RCxTQUFTLEdBQUc7QUFDUixZQUFRLE1BQU0sZ0NBQWdDLENBQUM7QUFDL0MsV0FBTyxDQUFDLE9BQU8sSUFBSSxFQUFFO0FBQUEsRUFDekI7QUFDSjtBQU9BLGVBQWUsbUJBQW1CQyxXQUFrQixRQUFnQixPQUFlO0FBQy9FLE1BQUk7QUFFQSxVQUFNLGtCQUFrQixNQUFNLFNBQVMsUUFBUSxNQUFNLElBQUk7QUFJekQsVUFBTSxlQUFlLE1BQU0scUJBQXFCLGlCQUFpQixLQUFLO0FBRXRFLFVBQU0sYUFBYSxLQUFLLFVBQVU7QUFBQSxNQUM5QixXQUFXO0FBQUEsSUFDZixDQUFDO0FBR0QsVUFBTSxhQUFhLE1BQU0sWUFBWUEsV0FBVSxRQUFRLFVBQVU7QUFFakUsUUFBSSxDQUFDLFdBQVcsU0FBUztBQUNyQixjQUFRLElBQUksaUNBQThCLFdBQVcsWUFBWTtBQUFBLElBQ3JFLE9BQU87QUFDSCxjQUFRLElBQUksdUJBQWlCLE1BQU07QUFBQSxJQUN2QztBQUFBLEVBQ0osU0FBUyxHQUFHO0FBQ1IsWUFBUSxNQUFNLG9DQUFvQyxDQUFDO0FBQUEsRUFDdkQ7QUFDSjsiLAogICJuYW1lcyI6IFsibWVzc2FnZSIsICJtZXNzYWdlIiwgInJlY2VpdmVyIiwgIm1lc3NhZ2UiLCAicmVjZWl2ZXIiXQp9Cg==
