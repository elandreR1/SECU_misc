// All message types between the application and the server
// Message for user name
export class CasUserName {
    constructor(public username: string) { }
}


// Message for requiring history
export class HistoryRequest {
    constructor(public agentName: string, public index: number) { }
}

// Result of history request
export class HistoryAnswer {
    constructor(public success: boolean,
        public failureMessage: string,
        public index: number,
        public allMessages: ExtMessage[]) { }
}

// Filtering of messages
export class FilterRequest {
    constructor(public from: string, public to: string, public indexmin: string) { }
}

export class FilteredMessage {
    constructor(public message: ExtMessage,
        public index: number,
        public deleted: boolean,
        public deleter: string) { }
}

// Result of filtering request
export class FilteringAnswer {
    constructor(public success: boolean,
        public failureMessage: string,
        public allMessages: FilteredMessage[]) { }
}

// Sending a message Result format
export class SendResult {
    constructor(public success: boolean, public errorMessage: string) { }
}

// Sending messages
// The message format
export class ExtMessage {
    constructor(public sender: string, public receiver: string, public content: string) { }
}

export class DeletingRequest {
    constructor(
        public indexToDelete: string) { }
}

export class DeletingAnswer {
    constructor(public success: boolean,
        message: string) { }
}

// Requesting keys
export class KeyRequest {
    constructor(public ownerOfTheKey: string, public publicKey: boolean, public encryption: boolean) { }
}

export class KeyResult {
    constructor(public success: boolean, public key: string, public errorMessage: string) { }
}