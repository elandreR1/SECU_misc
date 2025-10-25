import {
    encryptWithPublicKey, decryptWithPrivateKey, stringToPrivateKeyForEncryption, stringToPublicKeyForEncryption,
    stringToPrivateKeyForSignature,
    stringToPublicKeyForSignature, privateKeyToString, hash,
    signWithPrivateKey,
    verifySignatureWithPublicKey,
    generateNonce
} from './libCrypto'

import {
    HistoryAnswer, HistoryRequest, KeyRequest, KeyResult, CasUserName, ExtMessage, SendResult,

} from './serverMessages'

// To detect if we can use window.crypto.subtle
if (!window.isSecureContext) alert("Not secure context!")

//Index of the last read message
let lastIndexInHistory = 0

const userButtonLabel = document.getElementById("user-name") as HTMLLabelElement
const sendButton = document.getElementById("send-button") as HTMLButtonElement
const receiver = document.getElementById("receiver") as HTMLInputElement
const message = document.getElementById("message") as HTMLInputElement
const received_messages = document.getElementById("exchanged-messages") as HTMLLabelElement

function clearingMessages() {
    received_messages.textContent = ""
}

function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingReceivedMessage(message: string) {
    received_messages.append(stringToHTML('<p></p><p></p>' + message))
}

/* Name of the user of the application... can be Alice/Bob for attacking purposes */
let globalUserName = ""

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
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

async function setCasName() {
    globalUserName = await fetchCasName()
    // We replace the name of the user of the application as the default name
    // In the window
    userButtonLabel.textContent = globalUserName
    loadNonces() //utilisation de loadNonces() pour restaurer le tableau et ainsi vérifier les nonces qui transitent apres reconnexion
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


const keyCache : {[key:string] : CryptoKey} = {} //tableau pour stocker les clés pour éviter de les redemandés à chaque fois

async function fetchKey(user: string, publicKey: boolean, encryption: boolean): Promise<CryptoKey> {
    // Mise en cache locale pour éviter de redemander la clé à chaque appel
    const keyId = `${user}-${publicKey ? 'pub' : 'priv'}-${encryption ? 'enc' : 'sig'}`
    
    if (keyCache[keyId]) {
        return keyCache[keyId]
    }

    const keyRequestMessage = new KeyRequest(user, publicKey, encryption)
    const urlParams = new URLSearchParams(window.location.search)

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

    const keyResult = (await keyrequest.json()) as KeyResult
    if (!keyResult.success) throw new Error(keyResult.errorMessage)

    let key: CryptoKey
    if (publicKey && encryption) key = await stringToPublicKeyForEncryption(keyResult.key)
    else if (!publicKey && encryption) key = await stringToPrivateKeyForEncryption(keyResult.key)
    else if (publicKey && !encryption) key = await stringToPublicKeyForSignature(keyResult.key)
    else key = await stringToPrivateKeyForSignature(keyResult.key)

    keyCache[keyId] = key
    return key
}

async function sendMessage(agentName: string, receiverName: string, messageContent: string): Promise<SendResult> {
    try {
        let messageToSend =
            new ExtMessage(agentName, receiverName, messageContent)
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
        // Dealing with the answer of the message server
        return (await request.json()) as SendResult
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return new SendResult(false, error.message)
        } else {
            console.log('unexpected error: ', error);
            return new SendResult(false, 'An unexpected error occurred')
        }
    }
}

// function for refreshing the content of the window (automatic or manual see below)
async function refresh() {

    //Propriété 4 : Tolérance à l’asynchronisme
    // Cette fonction permet à un utilisateur de récupérer des messages même s’il était déconnecté

    try {
        const user = globalUserName
        const historyRequest =
            new HistoryRequest(user, lastIndexInHistory)
        const urlParams = new URLSearchParams(window.location.search);
        const request = await fetch("/history/" + ownerName + "?" + urlParams
            , {
                method: "POST",
                body: JSON.stringify(historyRequest),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            });
        if (!request.ok) {
            throw new Error(`Error! status: ${request.status} `);
        }
        const result = (await request.json()) as HistoryAnswer
        if (!result.success) { alert(result.failureMessage) }
        else {
            lastIndexInHistory = result.index
            for (const m of result.allMessages) {
                const [isValid, sender, clearMessage] = await analyseMessage(m)
                if (isValid) {
                    addingReceivedMessage(`${sender} -> ${user} : ${clearMessage}`)
                } else {
                    console.log("Message invalide ou non déchiffrable")
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

// Automatic refresh
const intervalRefresh = setInterval(refresh, 2000)

//Tableau de nonce utilisé pour vérifier les ACK (Propriété 3)
const verifNonce: {
    [nonce: string]: { receiver: string, message: string }
} = {}

// fonction pour stocker les nonces dans un tableau (Propriété 5)
function saveNonces() {
    localStorage.setItem("nonces", JSON.stringify(verifNonce))
}

//fonction pour mettre les nonces du tableau verifNonce dans le localStorage (Propriété 5)
function loadNonces() {
    const stored = localStorage.getItem("nonces")
    if (stored) Object.assign(verifNonce, JSON.parse(stored))
}

sendButton.onclick = async function () {
    const agentName = globalUserName
    const receiverName = receiver.value.trim()
    const msg = message.value.trim()

    if (receiverName === "" || msg === "") {
        alert("Veuillez remplir tous les champs.")
        return
    }

    try {
         // Propriété 3 : Nonce unique pour l’ACK
        const nonce = generateNonce()
        verifNonce[nonce] = {
            receiver: receiverName,
            message: msg
        }

        saveNonces() // après création on sauvegarde le nonce 


        // Création du contenu clair du message à chiffrer
        const payload = {
            msg,
            nonce
        }
      
        //ici on a décidé de respecter le protocole suivant A → B : A, { { m, Na }pk(B) }sk(A) 
        //                                                  B → A : B, { Na }pk(A)

        // Propriété 1 : Confidentialité - chiffrement avec la clé publique du destinataire

        const receiverPublicKey = await fetchKey(receiverName, true, true)
        const encryptedMessage = await encryptWithPublicKey(receiverPublicKey, JSON.stringify(payload))

        // Propriété 2 : Authentification - signature avec la clé privée de l’expéditeur

        const signMessage = await fetchKey(agentName, false, false)
        const MessSign = await signWithPrivateKey(signMessage, encryptedMessage)

        // Enveloppe finale à envoyer. On utilise JSON.stringify(...) pour transformer cet objet en une **chaîne de caractères** au format JSON,
        // afin de l'envoyer comme `string` dans la requête HTTP.
        const signetMess = JSON.stringify({
            encrypted: encryptedMessage,
            signature: MessSign
        })


        // envoie du message 
        const sendResult = await sendMessage(agentName, receiverName, signetMess)


        // un test pour afficher une possible erreur d'envoie sinon l'affichage du message
        if (!sendResult.success) {
            console.log(sendResult.errorMessage)
        } else {
            console.log("Message envoyé avec succès")
            const time = readableTime()
            const textToAdd = `<font color="blue"> ${agentName} -> ${receiverName} : (${time}) ${msg} </font>`
            addingReceivedMessage(textToAdd)
            message.value = ""
        }
    } catch (e) {
        if (e instanceof Error) {
            console.log('error message: ', e.message)
        } else {
            console.log('unexpected error: ', e)
        }
    }
}





// Returning a string representing the current time in the format
// HH:MM:SS
function readableTime(): string {
    const now = new Date()
    const hours = now.getHours().toString()
    const minutes = now.getMinutes().toString()
    const seconds = now.getSeconds().toString()
    // Since getHours() etc return a decimal count for hours, etc. we explicitely add 0 when there
    // are no tens digit.
    return `${(hours.length === 1) ? "0" + hours : hours}:${(minutes.length === 1) ? "0" + minutes : minutes}:${(seconds.length === 1) ? "0" + seconds : seconds}`
}


async function analyseMessage(message: ExtMessage): Promise<[boolean, string, string]> {
    const user = globalUserName
    const sender = message.sender
    const content = message.content

    //erreur si le message n'est pas destiné à l'utilisateur actuellement connecté, alors on l'ignore.
    if (message.receiver !== user) return [false, "", ""]

    // Cas 1 : c’est un message ACK → { encrypted } sans signature
    try {

        //on décode le message reçu 
        const parsedAck = JSON.parse(content)
        
        //si dans le content il y a un encrypted et pas de signature
        if (parsedAck.encrypted && !parsedAck.signature) {
            //on recupère le contenu du message chiffré
            const encryptedAck = parsedAck.encrypted
            //on récupère la clé privée pour déchiffré
            const privateKey = await fetchKey(user, false, true)
            //on l'utilise pour déchiffré le message
            const decryptedNonce = await decryptWithPrivateKey(privateKey, encryptedAck)


            //avec le champ decryptedNonce qui correspond au nonce renvoyé on vérifie qu'il est dans le tableau
            const expected = verifNonce[decryptedNonce]

            // Si on trouve une entrée dans la table `verifNonce` pour ce nonce,
            // et que le message ACK provient bien du destinataire prévu (`sender`),
            // alors l'accusé de réception est considéré comme valide.

            if (expected && expected.receiver === sender) {
                 // On supprime le nonce du tableau car on a reçu l'accusé une seule fois
                delete verifNonce[decryptedNonce]
                // On sauvegarde la table mise à jour dans le localStorage pour la persistance
                saveNonces()
                 // On affiche un message indiquant que le destinataire a bien reçu notre message
                return [true, sender, `${readableTime()} - le message a été envoyé et reçu à ${readableTime()}`]
            } else {
                console.log("ACK reçu avec nonce inconnu :", decryptedNonce)
                return [false, "", ""]
            }
        }
    } catch (e) {
        // Pas un ACK ou JSON mal formé : on tente le message standard
    }

    // Cas 2 : message normal signé → { encrypted, signature }
    try {
        const parsedMsg = JSON.parse(content)
        const { encrypted, signature } = parsedMsg

        if (!encrypted || !signature) {
            console.log("Message mal formé (manque encrypted ou signature)")
            return [false, "", ""]
        }

        // Vérifie signature
        const senderPubKey = await fetchKey(sender, true, false)
        const valid = await verifySignatureWithPublicKey(senderPubKey, encrypted, signature)
        if (!valid) {
            console.log("Signature non valide")
            return [false, "", ""]
        }

        // Déchiffre
        const privateKey = await fetchKey(user, false, true)
        const decrypted = await decryptWithPrivateKey(privateKey, encrypted)

        // Maintenant qu’on a le clair, on peut parser
        const payload = JSON.parse(decrypted)
        const msg = payload.msg
        const nonce = payload.nonce

        if (!msg || !nonce) {
            console.log("Payload incomplet :", payload)
            return [false, "", ""]
        }

        // Envoie ACK
        await sendAcknowledgment(user, sender, nonce)

        return [true, sender, `${readableTime()} - ${msg}`]

    } catch (e) {
        console.error("Erreur dans analyseMessage :", e)
        return [false, "", ""]
    }
}




// envoie un ACK au destinataire d'origine du message (le sender).

async function sendAcknowledgment(receiver: string, sender: string, nonce: string) {
    try {
        // On chiffre uniquement le nonce brut (pas de JSON)
        const senderPublicKey = await fetchKey(sender, true, true)

        // On chiffre le nonce brut avec la clé publique du destinataire du ACK
        // Cela garantit que seul `sender` pourra déchiffrer ce message.   
        const encryptedAck = await encryptWithPublicKey(senderPublicKey, nonce)

        const ackMessage = JSON.stringify({
            encrypted: encryptedAck
        })

        // On envoie ce message chiffré de `receiver` (celui qui a reçu le message original) vers `sender` (celui qui a envoyé le message)
        const sendResult = await sendMessage(receiver, sender, ackMessage)

        if (!sendResult.success) {
            console.log(" Échec de l'envoi du ACK :", sendResult.errorMessage)
        } else {
            console.log(" ACK envoyé à", sender)
        }
    } catch (e) {
        console.error("Erreur dans sendAcknowledgment :", e)
    }
}

