
/* Source: https://gist.github.com/groundrace/b5141062b47dd96a5c21c93839d4b954 */

/* tsc --inlineSourceMap true -outFile JS/setKeys.js src/libCrypto.ts src/setKeys.ts --target es2015  */

import {
    generateAssymetricKeysForEncryption,
    publicKeyToString, privateKeyToString, generateAssymetricKeysForSignature
} from './libCrypto'

/* Application --------------------------------------------------------- */

/* getting the main objects from the dom */
/* Buttons */
const setKeys = document.getElementById("set-keys-button") as HTMLButtonElement
const serializeButton = document.getElementById("serialize-keys-button") as HTMLButtonElement

const success = document.getElementById("success-messages") as HTMLLabelElement
const emails = document.getElementById("emails") as HTMLTextAreaElement

function clearMessages() {
    success.textContent = ""
}

function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingReceivedMessage(message: string) {
    success.append(stringToHTML('<p></p><p></p>' + message))
}

function stringToStringArray(stringWithNewLines: string): string[] {
    return stringWithNewLines.split(/[\r\n]+/)
}

class KeySetting {
    constructor(public ownerOfTheKeys: String,
        public publicKeyEnc: String,
        public privateKeyEnc: String,
        public publicKeySign: String,
        public privateKeySign: String
    ) { }
}

class KeySettingResult {
    constructor(public success: boolean, public errorMessage: String) { }
}

async function settingOneKey(owner: string, publicKeyEnc: string, privateKeyEnc: string, publicKeySign: string, privateKeySign: string) {
    const urlParams = new URLSearchParams(window.location.search);
    const keySettingMessage = new KeySetting(owner, publicKeyEnc, privateKeyEnc, publicKeySign, privateKeySign)
    const keyrequest = await fetch("/setKey?" + urlParams, {
        method: "POST",
        body: JSON.stringify(keySettingMessage),
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
    if (!keyrequest.ok) {
        throw new Error(`Error! status: ${keyrequest.status}`);
    }
    const keyResult = (await keyrequest.json()) as KeySettingResult;
    if (!keyResult.success) alert(keyResult.errorMessage)
    else {
        addingReceivedMessage(owner)
    }
}

setKeys.onclick = async function () {
    clearMessages()
    const allEmails = stringToStringArray(emails.value)
    for (let email of allEmails) {
        try {
            const keypairEnc: CryptoKey[] = await generateAssymetricKeysForEncryption()
            const publicKeyEncText = await publicKeyToString(keypairEnc[0])
            const privateKeyEncText = await privateKeyToString(keypairEnc[1])
            const keypairSign: CryptoKey[] = await generateAssymetricKeysForSignature()
            const publicKeySignText = await publicKeyToString(keypairSign[0])
            const privateKeySignText = await privateKeyToString(keypairSign[1])
            settingOneKey(email, publicKeyEncText, privateKeyEncText, publicKeySignText, privateKeySignText)
        } catch (e) {
            if (e instanceof DOMException) { alert("Generation failed!") }
            else { alert(e) }
        }
    }
}

class SerializeRequest {
    constructor(public b: boolean) { }
}

serializeButton.onclick = async function () {
    const serializeRequest =
        new SerializeRequest(true)
    const urlParams = new URLSearchParams(window.location.search);
    const keyrequest = await fetch("/serializeKeys?" + urlParams, {
        method: "POST",
        body: JSON.stringify(serializeRequest),
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
}