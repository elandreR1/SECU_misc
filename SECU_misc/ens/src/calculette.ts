
/* Source: https://gist.github.com/groundrace/b5141062b47dd96a5c21c93839d4b954 */

/* tsc --inlineSourceMap true -outFile JS/calculette.js src/libCrypto.ts src/calculette.ts --target es2015  */

import {
    encryptWithPublicKey, decryptWithPrivateKey,
    generateSymetricKey, generateNonce, encryptWithSymmetricKey, decryptWithSymmetricKey,
    generateAssymetricKeysForEncryption, stringToPrivateKeyForEncryption, stringToPublicKeyForEncryption, hash,
    stringToSymmetricKey, publicKeyToString, privateKeyToString, symmetricKeyToString, stringToPrivateKeyForSignature,
    stringToPublicKeyForSignature, signWithPrivateKey, verifySignatureWithPublicKey
} from './libCrypto'


/* Application --------------------------------------------------------- */

/* getting the main objects from the dom */
/* Buttons */
const rsaEncryptButton = document.getElementById("rsa-encrypt-button") as HTMLButtonElement
const rsaDecryptButton = document.getElementById("rsa-decrypt-button") as HTMLButtonElement
const rsaSignButton = document.getElementById("rsa-sign-button") as HTMLButtonElement
const rsaVerifyButton = document.getElementById("rsa-verify-button") as HTMLButtonElement
const generateAsymEncKeysButton = document.getElementById("generate-asym-enc-keys-button") as HTMLButtonElement
//const generateAsymSignKeysButton = document.getElementById("generate-asym-sign-keys-button") as HTMLButtonElement

const generateNonceButton = document.getElementById("generate-nonce-button") as HTMLButtonElement
const hashButton = document.getElementById("hash-button") as HTMLButtonElement

const generateSymKeyButton = document.getElementById("generate-symkey-button") as HTMLButtonElement
const aesEncryptButton = document.getElementById("aes-encrypt-button") as HTMLButtonElement
const aesDecryptButton = document.getElementById("aes-decrypt-button") as HTMLButtonElement


/* labels and input fields */
const publicKeyEncElement = document.getElementById("gen-public-key-enc") as HTMLTextAreaElement
const privateKeyEncElement = document.getElementById("gen-private-key-enc") as HTMLTextAreaElement
const publicKeySignElement = document.getElementById("gen-public-key-sign") as HTMLTextAreaElement
const privateKeySignElement = document.getElementById("gen-private-key-sign") as HTMLTextAreaElement

const symmetricKeyElement = document.getElementById("gen-symmetric-key") as HTMLTextAreaElement
const aesKeyEncrypt = document.getElementById("aes-encrypt-key") as HTMLTextAreaElement
const aesKeyDecrypt = document.getElementById("aes-decrypt-key") as HTMLTextAreaElement

const rsaMessageBox = document.getElementById("rsa-oaep-message") as HTMLTextAreaElement
const aesEncryptMessageBox = document.getElementById("aes-encrypt-message") as HTMLTextAreaElement
const aesDecryptMessageBox = document.getElementById("aes-decrypt-message") as HTMLTextAreaElement

const publicKeyEncBox = document.getElementById("rsa-pubkey-enc") as HTMLTextAreaElement
const privateKeyEncBox = document.getElementById("rsa-privkey-enc") as HTMLTextAreaElement
const publicKeySignBox = document.getElementById("rsa-pubkey-sign") as HTMLTextAreaElement
const privateKeySignBox = document.getElementById("rsa-privkey-sign") as HTMLTextAreaElement
const aesEncryptKey = document.getElementById("aes-encrypt-key") as HTMLTextAreaElement
const aesDecryptKey = document.getElementById("aes-decrypt-key") as HTMLTextAreaElement

const cypherTextElement = document.getElementById("cyphertext-value") as HTMLTextAreaElement
const messageToDecryptBox = document.getElementById("message-to-decrypt") as HTMLTextAreaElement
const decypheredTextElement = document.getElementById("decyphertext-value") as HTMLTextAreaElement

const messageToSign = document.getElementById("message-to-sign") as HTMLTextAreaElement
const signedMessage = document.getElementById("signed-value") as HTMLTextAreaElement

const signedMessageToCheck = document.getElementById("signed-message-to-check") as HTMLTextAreaElement
const signedMessageInClear = document.getElementById("signed-message-in-clear") as HTMLTextAreaElement
const rsaPublicKeyForVerification = document.getElementById("rsa-public-sign") as HTMLTextAreaElement
const verificationValue = document.getElementById("verification-value") as HTMLTextAreaElement

const messageToHash = document.getElementById("message-to-hash") as HTMLTextAreaElement
const hashedMessage = document.getElementById("hashed-message") as HTMLTextAreaElement

const aesCypherTextElement = document.getElementById("aes-cyphertext-value") as HTMLTextAreaElement
const aesCypherIV = document.getElementById("aes-cyphertext-IV") as HTMLTextAreaElement
const aesMessageToDecryptBox = document.getElementById("aes-message-to-decrypt") as HTMLTextAreaElement
const aesIVToDecryptBox = document.getElementById("aes-decrypt-IV") as HTMLTextAreaElement
const aesDecypheredTextElement = document.getElementById("aes-decyphertext-value") as HTMLTextAreaElement

const nonceTextElement = document.getElementById("nonce") as HTMLLabelElement

generateAsymEncKeysButton.onclick = async function () {
    try {
        const keypair: CryptoKey[] = await generateAssymetricKeysForEncryption()
        const publicKeyText = await publicKeyToString(keypair[0])
        const privateKeyText = await privateKeyToString(keypair[1])
        publicKeyEncElement.value = publicKeyText
        privateKeyEncElement.value = privateKeyText
    } catch (e) {
        if (e instanceof DOMException) { alert("Generation failed!") }
        else { alert(e) }
    }
}

// generateAsymSignKeysButton.onclick = async function () {
//     try {
//         const keypair: CryptoKey[] = await generateAssymetricKeysForSignature()
//         const publicKeyText = await publicKeyToString(keypair[0])
//         const privateKeyText = await privateKeyToString(keypair[1])
//         publicKeySignElement.value = publicKeyText
//         privateKeySignElement.value = privateKeyText
//     } catch (e) {
//         if (e instanceof DOMException) { alert("Generation failed!") }
//         else { alert(e) }
//     }
// }

generateSymKeyButton.onclick = async function () {
    try {
        const key: CryptoKey = await generateSymetricKey()
        const keyText = await symmetricKeyToString(key)
        symmetricKeyElement.value = keyText
    } catch (e) {
        if (e instanceof DOMException) { alert("Generation failed!") }
        else { alert(e) }
    }
}

generateNonceButton.onclick = function () {
    const nonce = generateNonce()
    nonceTextElement.textContent = nonce
}

hashButton.onclick = async function () {
    const textToHash = messageToHash.value
    hashedMessage.value = await hash(textToHash)
}

rsaEncryptButton.onclick = async function () {
    try {
        const message = rsaMessageBox.value
        const publicKeyTextBase64: string = publicKeyEncBox.value
        const publicKey: CryptoKey = await stringToPublicKeyForEncryption(publicKeyTextBase64)
        const encryptedMessage: string = await encryptWithPublicKey(publicKey, message)
        cypherTextElement.value = encryptedMessage
    } catch (e) {
        alert("Encryption failed!")
    }
}

rsaSignButton.onclick = async function () {
    try {
        const message = messageToSign.value
        const privateKeyTextBase64: string = privateKeySignBox.value
        const privateKey: CryptoKey = await stringToPrivateKeyForSignature(privateKeyTextBase64)
        const resultingSignedMessage: string = await signWithPrivateKey(privateKey, message)
        signedMessage.value = resultingSignedMessage
    } catch (e) {
        alert("Signature failed!")
    }
}


rsaVerifyButton.onclick = async function () {
    try {
        const signedMessage = signedMessageToCheck.value
        const messageInClear = signedMessageInClear.value
        const publicKeyTextBase64: string = publicKeySignBox.value
        const publicKey: CryptoKey = await stringToPublicKeyForSignature(publicKeyTextBase64)
        const verification: boolean = await verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage)
        verificationValue.value = "" + verification
    } catch (e) {
        alert("Signature failed!")
    }
}

aesEncryptButton.onclick = async function () {
    try {
        const message = aesEncryptMessageBox.value
        const keyTextBase64: string = aesEncryptKey.value
        const key: CryptoKey = await stringToSymmetricKey(keyTextBase64)
        const result: string[] = await encryptWithSymmetricKey(key, message)
        aesCypherTextElement.value = result[0]
        aesCypherIV.value = result[1]
    } catch (e) {
        alert("Encryption failed!")
    }
}

rsaDecryptButton.onclick = async function () {
    try {
        const message = messageToDecryptBox.value
        const privateKeyTextBase64: string = privateKeyEncBox.value
        const privateKey: CryptoKey = await stringToPrivateKeyForEncryption(privateKeyTextBase64)
        const decryptedMessage: string = await decryptWithPrivateKey(privateKey, message)
        decypheredTextElement.value = decryptedMessage
    } catch (e) {
        alert("Decryption failed")
    }
}


aesDecryptButton.onclick = async function () {
    try {
        const message = aesDecryptMessageBox.value
        const keyTextBase64: string = aesDecryptKey.value
        const key: CryptoKey = await stringToSymmetricKey(keyTextBase64)
        const initVector: string = aesIVToDecryptBox.value
        const result: string = await decryptWithSymmetricKey(key, message, initVector)
        aesDecypheredTextElement.value = result
    } catch (e) {
        alert("Decryption failed!")
    }
}