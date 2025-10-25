/* Source: https://gist.github.com/groundrace/b5141062b47dd96a5c21c93839d4b954 */

/* Available functions:

    # Key/nonce generation:
    generateAssymetricKeysForEncryption(): Promise<CryptoKey[]>
    generateAssymetricKeysForSignature(): Promise<CryptoKey[]>
    generateSymetricKey(): Promise<CryptoKey>
    generateNonce(): string

    # Assymetric key Encryption/Decryption/Signature/Signature verification
    encryptWithPublicKey(pkey: CryptoKey, message: string): Promise<string>
    decryptWithPrivateKey(skey: CryptoKey, message: string): Promise<string>
    signWithPrivateKey(privateKey: CryptoKey, message: string): Promise<string>
    verifySignatureWithPublicKey(publicKey: CryptoKey, messageInClear: string, signedMessage: string): Promise<boolean>

    # Symmetric key Encryption/Decryption
    encryptWithSymmetricKey(key: CryptoKey, message: string): Promise<string[]>
    decryptWithSymmetricKey(key: CryptoKey, message: string, initVector: string): Promise<string>

    # Importing keys from string
    stringToPublicKeyForEncryption(pkeyInBase64: string): Promise<CryptoKey>
    stringToPrivateKeyForEncryption(skeyInBase64: string): Promise<CryptoKey>
    stringToPublicKeyForSignature(pkeyInBase64: string): Promise<CryptoKey>
    stringToPrivateKeyForSignature(skeyInBase64: string): Promise<CryptoKey>
    stringToSymmetricKey(skeyBase64: string): Promise<CryptoKey>

    # Exporting keys to string
    publicKeyToString(key: CryptoKey): Promise<string>
    privateKeyToString(key: CryptoKey): Promise<string>
    symmetricKeyToString(key: CryptoKey): Promise<string>

    # Hashing
    hash(text: string): Promise<string>
*/

// LibCrypto---------------------------------------------------------------------------

/*
Imports the given public key (for encryption) from the import space.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
export async function stringToPublicKeyForEncryption(pkeyBase64: string): Promise<CryptoKey> {
    try {
        const keyArrayBuffer: ArrayBuffer = base64StringToArrayBuffer(pkeyBase64)
        const key: CryptoKey = await window.crypto.subtle.importKey(
            "spki",
            keyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["encrypt"]
        )
        return key
    } catch (e) {
        if (e instanceof DOMException) { console.log("String for the public key (for encryption) is ill-formed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("String for the public key (for encryption) is ill-formed!") }
        else { console.log(e) }
        throw e
    }
}

/*
Imports the given public key (for signature verification) from the import space.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
export async function stringToPublicKeyForSignature(pkeyBase64: string): Promise<CryptoKey> {
    try {
        const keyArrayBuffer: ArrayBuffer = base64StringToArrayBuffer(pkeyBase64)
        const key: CryptoKey = await window.crypto.subtle.importKey(
            "spki",
            keyArrayBuffer,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256",
            },
            true,
            ["verify"]
        )
        return key
    } catch (e) {
        if (e instanceof DOMException) { console.log("String for the public key (for signature verification) is ill-formed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("String for the public key (for signature verification) is ill-formed!") }
        else { console.log(e) }
        throw e
    }
}

/*
Imports the given private key (in string) as a valid private key (for decryption)
The SubtleCrypto imposes to use the "pkcs8" ?? format for importing public keys.
*/
export async function stringToPrivateKeyForEncryption(skeyBase64: string): Promise<CryptoKey> {
    try {
        const keyArrayBuffer: ArrayBuffer = base64StringToArrayBuffer(skeyBase64)
        const key: CryptoKey = await window.crypto.subtle.importKey(
            "pkcs8",
            keyArrayBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["decrypt"])
        return key
    } catch (e) {
        if (e instanceof DOMException) { console.log("String for the private key (for decryption) is ill-formed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("String for the private key (for decryption) is ill-formed!") }
        else { console.log(e) }
        throw e
    }
}

/*
Imports the given private key (in string) as a valid private key (for signature)
The SubtleCrypto imposes to use the "pkcs8" ?? format for importing public keys.
*/
export async function stringToPrivateKeyForSignature(skeyBase64: string): Promise<CryptoKey> {
    try {
        const keyArrayBuffer: ArrayBuffer = base64StringToArrayBuffer(skeyBase64)
        const key: CryptoKey = await window.crypto.subtle.importKey(
            "pkcs8",
            keyArrayBuffer,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256",
            },
            true,
            ["sign"])
        return key
    } catch (e) {
        if (e instanceof DOMException) { console.log("String for the private key (for signature) is ill-formed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("String for the private key (for signature) is ill-formed!") }
        else { console.log(e) }
        throw e
    }
}
/*
Exports the given public key into a valid string.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/

export async function publicKeyToString(key: CryptoKey): Promise<string> {
    const exportedKey: ArrayBuffer = await window.crypto.subtle.exportKey("spki", key)
    return arrayBufferToBase64String(exportedKey)
}

/*
Exports the given public key into a valid string.
The SubtleCrypto imposes to use the "spki" format for exporting public keys.
*/
export async function privateKeyToString(key: CryptoKey): Promise<string> {
    const exportedKey: ArrayBuffer = await window.crypto.subtle.exportKey("pkcs8", key)
    return arrayBufferToBase64String(exportedKey)
}

/* Generates a pair of public and private RSA keys for encryption/decryption */
export async function generateAssymetricKeysForEncryption(): Promise<CryptoKey[]> {
    const keypair: CryptoKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    )
    return [keypair.publicKey, keypair.privateKey]
}

/* Generates a pair of public and private RSA keys for signing/verifying */
export async function generateAssymetricKeysForSignature(): Promise<CryptoKey[]> {
    const keypair: CryptoKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
    )
    return [keypair.publicKey, keypair.privateKey]
}

/* Generates a random nonce */
export function generateNonce(): string {
    const nonceArray = new Uint32Array(1)
    self.crypto.getRandomValues(nonceArray)
    return nonceArray[0].toString()
}

/* Encrypts a message with a public key */
export async function encryptWithPublicKey(publicKey: CryptoKey, message: string): Promise<string> {
    try {
        const messageToArrayBuffer = textToArrayBuffer(message)
        const cypheredMessageAB: ArrayBuffer = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            messageToArrayBuffer
        )
        return arrayBufferToBase64String(cypheredMessageAB)
    } catch (e) {
        if (e instanceof DOMException) { console.log(e); console.log("Encryption failed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("Public key or message to encrypt is ill-formed") }
        else { console.log(e) }
        throw e
    }
}

/* Sign a message with a private key */
export async function signWithPrivateKey(privateKey: CryptoKey, message: string): Promise<string> {
    try {
        const messageToArrayBuffer = textToArrayBuffer(message)
        const signedMessageAB: ArrayBuffer = await window.crypto.subtle.sign(
            "RSASSA-PKCS1-v1_5",
            privateKey,
            messageToArrayBuffer
        )
        return arrayBufferToBase64String(signedMessageAB)
    } catch (e) {
        if (e instanceof DOMException) { console.log(e); console.log("Signature failed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("Private key or message to sign is ill-formed") }
        else { console.log(e) }
        throw e
    }
}


/* Decrypts a message with a private key */
export async function decryptWithPrivateKey(privateKey: CryptoKey, message: string): Promise<string> {
    try {
        const decrytpedMessageAB: ArrayBuffer = await
            window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                base64StringToArrayBuffer(message)
            )
        return arrayBufferToText(decrytpedMessageAB)
    } catch (e) {
        if (e instanceof DOMException) {
            console.log("Invalid key, message or algorithm for decryption")
        } else if (e instanceof KeyStringCorrupted) {
            console.log("Private key or message to decrypt is ill-formed")
        }
        else console.log("Decryption failed")
        throw e
    }
}


/* Verification of a signature on a message with a public key */
export async function verifySignatureWithPublicKey(publicKey: CryptoKey, messageInClear: string, signedMessage: string): Promise<boolean> {
    try {
        const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage)
        const messageInClearToArrayBuffer = textToArrayBuffer(messageInClear)
        const verified: boolean = await
            window.crypto.subtle.verify(
                "RSASSA-PKCS1-v1_5",
                publicKey,
                signedToArrayBuffer,
                messageInClearToArrayBuffer)
        return verified
    } catch (e) {
        if (e instanceof DOMException) {
            console.log("Invalid key, message or algorithm for signature verification")
        } else if (e instanceof KeyStringCorrupted) {
            console.log("Public key or signed message to verify is ill-formed")
        }
        else console.log("Decryption failed")
        throw e
    }
}


/* Generates a symmetric AES-GCM key */
export async function generateSymetricKey(): Promise<CryptoKey> {
    const key: CryptoKey = await window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    )
    return key
}

/* a symmetric AES key into a string */
export async function symmetricKeyToString(key: CryptoKey): Promise<string> {
    const exportedKey: ArrayBuffer = await window.crypto.subtle.exportKey("raw", key)
    return arrayBufferToBase64String(exportedKey)
}

/* Imports the given key (in string) as a valid AES key */
export async function stringToSymmetricKey(skeyBase64: string): Promise<CryptoKey> {
    try {
        const keyArrayBuffer: ArrayBuffer = base64StringToArrayBuffer(skeyBase64)
        const key: CryptoKey = await window.crypto.subtle.importKey(
            "raw",
            keyArrayBuffer,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"])
        return key
    } catch (e) {
        if (e instanceof DOMException) { console.log("String for the symmetric key is ill-formed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("String for the symmetric key is ill-formed!") }
        else { console.log(e) }
        throw e
    }
}


// When cyphering a message with a key in AES, we obtain a cyphered message and an "initialisation vector".
// In this implementation, the output is a two elements array t such that t[0] is the cyphered message
// and t[1] is the initialisation vector. To simplify, the initialisation vector is represented by a string.
// The initialisation vectore is used for protecting the encryption, i.e, 2 encryptions of the same message 
// with the same key will never result into the same encrypted message.
// 
// Note that for decyphering, the **same** initialisation vector will be needed.
// This vector can safely be transferred in clear with the encrypted message.

export async function encryptWithSymmetricKey(key: CryptoKey, message: string): Promise<string[]> {
    try {
        const messageToArrayBuffer = textToArrayBuffer(message)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ivText = arrayBufferToBase64String(iv)
        const cypheredMessageAB: ArrayBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            messageToArrayBuffer
        )
        return [arrayBufferToBase64String(cypheredMessageAB), ivText]
    } catch (e) {
        if (e instanceof DOMException) { console.log(e); console.log("Encryption failed!") }
        else if (e instanceof KeyStringCorrupted) { console.log("Symmetric key or message to encrypt is ill-formed") }
        else { console.log(e) }
        throw e
    }
}

// For decyphering, we need the key, the cyphered message and the initialization vector. See above the 
// comments for the encryptWithSymmetricKey function
export async function decryptWithSymmetricKey(key: CryptoKey, message: string, initVector: string): Promise<string> {
    const decodedInitVector: ArrayBuffer = base64StringToArrayBuffer(initVector)
    try {
        const decrytpedMessageAB: ArrayBuffer = await
            window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: decodedInitVector },
                key,
                base64StringToArrayBuffer(message)
            )
        return arrayBufferToText(decrytpedMessageAB)
    } catch (e) {
        if (e instanceof DOMException) {
            console.log("Invalid key, message or algorithm for decryption")
        } else if (e instanceof KeyStringCorrupted) {
            console.log("Symmetric key or message to decrypt is ill-formed")
        }
        else console.log("Decryption failed")
        throw e
    }
}

// SHA-256 Hash from a text
export async function hash(text: string): Promise<string> {
    const text2arrayBuf = textToArrayBuffer(text)
    const hashedArray = await window.crypto.subtle.digest("SHA-256", text2arrayBuf)
    return arrayBufferToBase64String(hashedArray)
}

class KeyStringCorrupted extends Error { }

// ArrayBuffer to a Base64 string
function arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string {
    var byteArray = new Uint8Array(arrayBuffer)
    var byteString = ''
    for (var i = 0; i < byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i])
    }
    return btoa(byteString)
}

// Base64 string to an arrayBuffer
function base64StringToArrayBuffer(b64str: string): ArrayBuffer {
    try {
        var byteStr = atob(b64str)
        var bytes = new Uint8Array(byteStr.length)
        for (var i = 0; i < byteStr.length; i++) {
            bytes[i] = byteStr.charCodeAt(i)
        }
        return bytes.buffer
    } catch (e) {
        console.log(`String starting by '${b64str.substring(0, 10)}' cannot be converted to a valid key or message`)
        throw new KeyStringCorrupted
    }
}

// String to array buffer
function textToArrayBuffer(str: string): ArrayBuffer {
    var buf = encodeURIComponent(str) // 2 bytes for each char
    var bufView = new Uint8Array(buf.length)
    for (var i = 0; i < buf.length; i++) {
        bufView[i] = buf.charCodeAt(i)
    }
    return bufView
}

// Array buffers to string
function arrayBufferToText(arrayBuffer: ArrayBuffer): string {
    var byteArray = new Uint8Array(arrayBuffer)
    var str = ''
    for (var i = 0; i < byteArray.byteLength; i++) {
        str += String.fromCharCode(byteArray[i])
    }
    return decodeURIComponent(str)
}

