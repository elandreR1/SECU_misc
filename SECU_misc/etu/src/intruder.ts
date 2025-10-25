/* tsc --inlineSourceMap true -outFile JS/intruder.js src/libCrypto.ts src/intruder.ts --target es2015 */

import {
    generateNonce,
    stringToPrivateKeyForEncryption, stringToPublicKeyForEncryption,
    publicKeyToString, privateKeyToString, stringToPrivateKeyForSignature,
    stringToPublicKeyForSignature,
} from './libCrypto'

import {
    DeletingRequest, DeletingAnswer, FilterRequest, FilteringAnswer, KeyRequest,
    KeyResult, CasUserName, ExtMessage, SendResult
} from './serverMessages'

const filterButton = document.getElementById("filter-button") as HTMLButtonElement
const sendButton = document.getElementById("send-button") as HTMLButtonElement
const deleteButton = document.getElementById("delete-button") as HTMLButtonElement
const getPublicKeyButton = document.getElementById("get-public-key-button") as HTMLButtonElement
const getPrivateKeyButton = document.getElementById("get-private-key-button") as HTMLButtonElement

const generateNonceButton = document.getElementById("generate-nonce-button") as HTMLButtonElement

const public_key_owner = document.getElementById("public-key-owner") as HTMLInputElement
const private_key_owner = document.getElementById("private-key-owner") as HTMLInputElement

const publicKeyElementEnc = document.getElementById("public-key-enc") as HTMLLabelElement
const privateKeyElementEnc = document.getElementById("private-key-enc") as HTMLLabelElement
const publicKeyElementSign = document.getElementById("public-key-sign") as HTMLLabelElement
const privateKeyElementSign = document.getElementById("private-key-sign") as HTMLLabelElement

const nonceTextElement = document.getElementById("nonce") as HTMLLabelElement

const from = document.getElementById("from") as HTMLInputElement
const to = document.getElementById("to") as HTMLInputElement
const indexminElt = document.getElementById("indexmin") as HTMLInputElement
const filtered_messages = document.getElementById("filtered-messages") as HTMLLabelElement

const sendfrom = document.getElementById("sendfrom") as HTMLInputElement
const sendto = document.getElementById("sendto") as HTMLInputElement
const sendcontent = document.getElementById("sendcontent") as HTMLInputElement
const deleteIndex = document.getElementById("deleteindex") as HTMLInputElement

async function fetchCasName(): Promise<string> {
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
    const nameResult = (await namerequest.json()) as CasUserName;
    return nameResult.username
}

// We set the default CAS name for the public key fields
async function setCasName() {
    public_key_owner.value = await fetchCasName()
    private_key_owner.value = await fetchCasName()
}
setCasName()

/* Name of the owner/developper of the application, i.e, the name of the folder 
   where the web page of the application is stored. E.g, for teachers' application
   this name is "ens" */

function getOwnerName(): string {
    const path = window.location.pathname
    const name = path.split("/", 2)[1]
    return name
}

let ownerName = getOwnerName()

function clearingMessages() {
    filtered_messages.textContent = ""
}

function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingFilteredMessage(message: string) {
    filtered_messages.append(stringToHTML('<p></p><p></p>' + message))
}

generateNonceButton.onclick = function () {
    const nonce = generateNonce()
    nonceTextElement.textContent = nonce
}

async function fetchKey(user: string, publicKey: boolean, encryption: boolean): Promise<CryptoKey> {
    // Getting the public/private key of user. 
    // For public key the boolean 'publicKey' is true.
    // For private key the boolean 'publicKey' is false.
    // If the key is used for encryption/decryption then the boolean 'encryption' is true.
    // If the key is used for signature/signature verification then the boolean is false.
    const keyRequestMessage =
        new KeyRequest(user, publicKey, encryption)
    // For CAS authentication we need to add the authentication ticket
    // It is contained in urlParams
    const urlParams = new URLSearchParams(window.location.search);
    // For getting a key we do not need the ownerName param
    // Because keys are independant of the applications
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
    const keyResult = (await keyrequest.json()) as KeyResult;
    if (!keyResult.success) alert(keyResult.errorMessage)
    else {
        if (publicKey) return await stringToPublicKeyForEncryption(keyResult.key)
        else return await stringToPrivateKeyForEncryption(keyResult.key)
    }
}

getPublicKeyButton.onclick = async function () {
    const public_key_owner_name = public_key_owner.value
    const publicKeyEnc = await fetchKey(public_key_owner_name, true, true)
    const publicKeySign = await fetchKey(public_key_owner_name, true, false)
    publicKeyElementEnc.textContent = await publicKeyToString(publicKeyEnc)
    publicKeyElementSign.textContent = await publicKeyToString(publicKeySign)
}

getPrivateKeyButton.onclick = async function () {
    const private_key_owner_name = private_key_owner.value
    const privateKeyEnc = await fetchKey(private_key_owner_name, false, true)
    const privateKeySign = await fetchKey(private_key_owner_name, false, false)
    privateKeyElementEnc.textContent = await privateKeyToString(privateKeyEnc)
    privateKeyElementSign.textContent = await privateKeyToString(privateKeySign)
}

deleteButton.onclick = async function () {
    let indexToDelete = deleteIndex.value
    const urlParams = new URLSearchParams(window.location.search);
    try {
        let deleteRequest =
            new DeletingRequest(indexToDelete)
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
        // Dealing with the answer of the message server
        return (await request.json()) as DeletingAnswer
    }
    catch (error) {
        if (error instanceof Error) {
            alert(error.message)
            //console.log('error message: ', error.message);
            return new DeletingAnswer(false, error.message)
        } else {
            console.log('unexpected error: ', error);
            return new DeletingAnswer(false, 'An unexpected error occurred')
        }
    }

}

async function sendMessage(agentName: string, receiverName: string, messageContent: string): Promise<SendResult> {
    try {
        let messageToSend = new ExtMessage(agentName, receiverName, messageContent)
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
        // Dealing with the answer of the message server
        return (await request.json()) as SendResult
    }
    catch (error) {
        if (error instanceof Error) {
            console.log(error.message)
            return new SendResult(false, error.message)
        } else {
            console.log(error)
            return new SendResult(false, 'An unexpected error occurred')
        }
    }
}

// the intruder sends a message in place of any user
sendButton.onclick = async function () {
    let agentName = sendfrom.value
    let receiverName = sendto.value
    let content = sendcontent.value
    try {
        const sendResult = await sendMessage(agentName, receiverName, content)
        if (!sendResult.success) alert(sendResult.errorMessage)
        else {
            console.log("Successfully sent the message!")
        }
    } catch (e) {
        if (e instanceof Error) {
            console.log(e.message)
        } else {
            console.log(e)
        }
    }
}

filterButton.onclick = async function () {
    try {
        const fromText = from.value
        const toText = to.value
        const indexmin = indexminElt.value
        const filterRequest =
            new FilterRequest(fromText, toText, indexmin)
        // For CAS authentication we need to add the authentication ticket
        // It is contained in urlParams
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
        const result = (await request.json()) as FilteringAnswer
        if (!result.success) { alert(result.failureMessage) }
        else {
            clearingMessages()
            for (var filt_message of result.allMessages) {
                if (filt_message.deleted) {
                    addingFilteredMessage(`Index: ${filt_message.index} Deleted by: ${filt_message.deleter} <strike> From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content} </strike>`)
                } else {
                    addingFilteredMessage(`Index: ${filt_message.index} From: ${filt_message.message.sender} To: ${filt_message.message.receiver} Content: ${filt_message.message.content}`)
                }
            }
        }
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return error.message;
        } else {
            console.log('unexpected error: ', error);
            return 'An unexpected error occurred';
        }
    }
}

