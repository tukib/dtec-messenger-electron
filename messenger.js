// Imported modules:
// ipcMain       <- electron.ipcMain : Event emitter module from Electron
// native_crypto <- crypto           : Native Node.js cryptography module 
// WebSocket     <- ws               : Simple WebSocket implementation module
// Store         <- electron-store   : Data persistance module for Electron
// ObjectID      <- mongodb.ObjectID : ObjectID parser/generator module from MongoDB
const {ipcMain} = require("electron")
const native_crypto = require("crypto")
const WebSocket = require("ws")
const Store = require('electron-store')
const store = new Store() // Initialise the store module (no need to specify store location)
const ObjectID = require("mongodb").ObjectID

// Main Client
// this handles networking and sends events to the front end for displaying information
class Client {
    constructor() {

        // create an instance of the Crypto class that is accessible inside any Client
        this.crypto = new Crypto()

        // Assigning variables
        // Client.pingTimeout      : Timeout ID for heartbeat/ping
        // Client.connected        : Whether the client is connected to the remote server
        // Client.username         : The username the client's public key is assigned to
        // Client.webContents      : References the BrowserWindow instance's contents to send events
        // Client.messageCache     : Temporary storage for messages when waiting on the server for information
        // Client.outgoingMessages : Outgoing messages are saved here before they are encrypted for message history
        this.pingTimeout = 0
        this.connected = false
        this.username = ""
        this.webContents = false
        this.messageCache = {}
        this.outgoingMessages = []

        const outgoingMessagesStore = store.get("outgoingMessages")
        if (outgoingMessagesStore) this.outgoingMessages = outgoingMessagesStore

        // Constants/config
        // Client.config.server_address : WebSocket address to connect to
        this.config = {
            server_address: "ws://ssh.ubuntu-cx31-tukib.hetzner-cloud.tukib.org:8080"
        }

        // Incoming events from BrowserWindow
        // register-submit : Attempt to register given username and password, login automatically after
        // login-submit    : Attempt login (Decrypt private key) with given password and validate with server
        // message-submit  : Attempt to send encrypted message to server with given message and recipient
        // reset           : Delete local storage and quit app instance (for testing)
        ipcMain.on("register-submit", (event, data) => this.register(data))
        ipcMain.on("login-submit", (event, data) => this.initLogin(data))
        ipcMain.on("message-submit", (event, data) => this.prepareTextMessage(data))
        ipcMain.on("reset", () => {
            store.delete("outgoingMessages")
            store.delete("key.generated")
            store.delete("key.publicKey")
            store.delete("key.privateKey")
            require("electron").app.quit()
        })

        // Attempt a connection to the server
        // TODO: reconnect when connection is closed
        this.connectToServer()
    }
    // Client.onWindowLoad( win: BrowserWindow ): void
    // Called when the BrowserWindow is initialised
    onWindowLoad(win) {
        this.webContents = win.webContents
        if (store.get("key.generated")) {
            this.webContents.send("show-login")
        } else {
            this.webContents.send("show-register")
        }
        this.startup()
    }
    // Client.connectToServer(): void
    // Called by constructor, starts and handles websocket connection and websocket events
    // TODO: reconnect after some time, just call this method again
    connectToServer() {
        const heartbeat = () => {
            clearTimeout(this.pingTimeout)
            this.pingTimeout = setTimeout(() => {
                this.connected = false
                this.ws.terminate()
            }, 11000)
        }
        this.ws = new WebSocket(this.config.server_address)
        this.ws.on("open", () => {
            this.connected = true
            heartbeat()
            console.log("connected")
            this.startup()
        })
        this.ws.on("ping", () => heartbeat())
        this.ws.on("close", () => {
            this.connected = false
            clearTimeout(this.pingTimeout)
        })
        this.ws.on("message", msg => {
            console.log(msg)
            const cmd = msg.substr(0, msg.indexOf(" "))
            const data = JSON.parse(msg.substr(msg.indexOf(" ") + 1))
            this.parseServerMessage(cmd, data)
        })
    }
    // Client.startup(): void
    // Called by websocket on open event and Client.onWindowLoad
    // Contains any actions that need to be run once the BrowserWindow and WebSocket is ready
    startup() {
        if (!this.webContents || !this.connected) return
        console.log("client ready")
    }
    // Client.parseServerMessage(cmd: string, data: object): void
    // Called by websocket on message event, parses data that the server sends and calls appropriate methods
    parseServerMessage(cmd, data) {
        if (cmd === "register_res") {
            this.registerResponse(data)
        } else if (cmd === "login_res") {
            this.username = data.username
            this.webContents.send("show-main")
            console.log("logged in as " + data.username)
            this.postLogin()
        } else if (cmd === "whois_res") {
            this.sendTextMessage(data)
        } else if (cmd === "msg_res") {
            this.handleTextMessageRes(data)
        } else if (cmd === "hist") {
            this.handleHistory(data)
        } else if (cmd === "new_msg") {
            this.handleNewMessage(data)
        }
    }
    // Client.send(cmd: string, data: object, sign: boolean = false): void
    // Turns data into a single string to be sent through the websocket (with an optional verification signature)
    send(cmd, data, sign=false) {
        data.t = Date.now()
        if (sign) data = [data, this.crypto.sign(JSON.stringify(data))]
        this.ws.send(cmd + " " + JSON.stringify(data))
    }
    // Client.register(data: object): void
    // Takes in a password and generates a key pair, then requests the server to assign the given username to the public key
    register(data) {
        if (!store.get("key.generated")) {
            console.log(data.password)
            this.crypto.passphrase = data.password
            this.crypto.generateKeyPair()
            console.log(this.crypto.publicKeyString)
            store.set("key.generated", true)
            store.set("key.publicKey", this.crypto.publicKeyString)
            store.set("key.privateKey", this.crypto.privateKeyString)
        }
        this.send("register", {username: data.username, publicKeyString: this.crypto.publicKeyString}, true)
    }
    // Client.registerResponse(data: object): void
    // Handles server response for register. On fail: show error, on success, request login
    registerResponse(data) {
        if (data.ok) {
            this.login()
        } else {
            this.webContents.send("register-failed", data.username)
        }
    }
    // Client.login(): void
    // Attempts to login to server using public key (+signature to verify owner of said key)
    login() {
        this.send("login", {publicKeyString: this.crypto.publicKeyString}, true)
    }
    // Client.initLogin(password: string): void
    // Called on browser event (login submit)
    // Attempts to load key pair using given password and if successful, attempt login
    initLogin(password) {
        this.crypto.passphrase = password
        this.crypto.publicKeyString = store.get("key.publicKey")
        this.crypto.privateKeyString = store.get("key.privateKey")
        if (this.crypto.loadKeys()) {
            this.login()
        } else {
            this.webContents.send("wrong-pass")
        }
    }
    // Client.prepareTextMessage(msg: string): void
    // Called on browser event (message submit)
    // Creates an ID, stores the message in Client.messageCache, and asks server for recipient public key
    prepareTextMessage(msg) {
        const id = (new ObjectID()).toHexString()
        this.messageCache[id] = msg
        this.webContents.send("msg-res", {
            type: "add",
            id: id,
            content: msg.content,
            to: msg.to,
            from: this.username,
            outgoing: true
        })
        this.send("whois", {
            user: msg.to,
            forMessage: id
        })
    }
    // Client.sendTextMessage(data: object): void
    // Called when server sends back public key for an outgoing message
    // Gets the stored message from Client.messageCache and encrypts the contents using the recipient public key and sends back to server
    sendTextMessage(data) {
        if (!data.ok) {
            return this.webContents.send("msg-res", {
                type: "error",
                id: data.forMessage,
                msg: "recipient does not exist"
            })
        }
        const msg = this.messageCache[data.forMessage]
        const encrypted_content = this.crypto.encryptContentFor(msg.content, data.publicKeyString)
        this.send("msg", {
            content: encrypted_content,
            to: msg.to,
            as: this.username,
            id: data.forMessage
        })
    }
    // Client.handleTextMessageRes(data: object): void
    // Called when the server sends back a response from the encrypted message we sent
    // Tells BrowserWindow whether the message was successful and stores the message locally for history
    handleTextMessageRes(data) {
        if (data.ok) {
            this.webContents.send("msg-res", {
                type: "fullsend",
                id: data.id
            })
            const msg = this.messageCache[data.id]
            this.outgoingMessages.push({
                _id: data.id,
                to: msg.to,
                from: this.username,
                time: data.r_t,
                local: true,
                content: msg.content
            })
            store.set("outgoingMessages", this.outgoingMessages)
        } else {
            this.webContents.send("msg-res", {
                type: "error",
                id: data.id,
                msg: "unknown error"
            })
        }
        delete this.messageCache[data.forMessage]
    }
    // Client.postLogin(): void
    // Called after successful login, requests message history from server
    postLogin() {
        this.send("get_hist", {as: this.username})
    }
    // Client.handleHistory(): void
    // Called after server sends back message history
    // This method merges the remote message history with local message history (Client.outgoingMessages)
    // Then, the (decrypted) messages will be sent to the BrowserWindow to be displayed
    handleHistory(data) {
        data.messages.push(...this.outgoingMessages)
        data.messages.sort((a, b) => a.time - b.time)
        for (var i = 0; i < data.messages.length; i++) {
            const msg = data.messages[i]
            this.webContents.send("msg-res", {
                type: "add",
                id: msg._id,
                content: msg.local ? msg.content : this.crypto.decryptContent(msg.content),
                to: msg.to,
                from: msg.from,
                outgoing: msg.local,
                notPending: true
            })
        }
    }
    // Client.handleNewMessage(): void
    // Called when received an emcrypted message from the server
    // Decrypts the contents and sends to BrowserWindow to be displayed
    handleNewMessage(data) {
        const msg = data.message
        this.webContents.send("msg-res", {
            type: "add",
            id: msg._id,
            content: this.crypto.decryptContent(msg.content),
            to: msg.to,
            from: msg.from
        })
    }
}

// Crypto class
// contains methods to simplify the cryptography used by the Client
class Crypto {
    constructor() {
        // Assigning variables
        // Crypto.passphrase       : passhrase to decrypt stored private key string
        // Crypto.publicKeyString  : Own public key string
        // Crypto.privateKeyString : Own private key string (encrypted)
        // Crypto.publicKeyObject  : Own public key object
        // Crypto.privateKeyObject : Own private key object (decrypted)
        this.passphrase = ""
        this.publicKeyString = ""
        this.privateKeyString = ""
        this.publicKeyObject = {}
        this.privateKeyObject = {}

        // config options for native crypto functions
        this.config = {
            // Crypto.config.keyPair : used for native_crypto.generateKeyPairSync
            keyPair: {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: "spki",
                    format: "pem"
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "pem",
                    cipher: "aes-256-cbc"
                    // passphrase: getter for Crypto.passphrase
                }
            }
        }
        // Set a getter in the keyPair generation config to get the set passphrase
        Object.defineProperty(this.config.keyPair.privateKeyEncoding, "passphrase", {
            get: () => this.passphrase
        })
    }
    // Crypto.generateKeyPair(): void
    // Generates a private and public key based on current config options, then loads them (Crypto.loadKeys())
    // Private key passphrase is obtained by the getter Crypto.config.keypair.privateKeyEncoding.passphrase (gets Crypto.passphrase)
    generateKeyPair() {
        const keys = native_crypto.generateKeyPairSync("rsa", this.config.keyPair)
        this.publicKeyString = keys.publicKey
        this.privateKeyString = keys.privateKey
        this.loadKeys()
    }
    // Crypto.loadKeys(): void
    // Attempts to load the private/public key pair and geneate key objects to be used for encryption/decryption/signing
    loadKeys() {
        /*this.publicKeyObject = native_crypto.createPublicKey({
            key: this.publicKeyString,
            format: this.config.keyPair.publicKeyEncoding.format,
            type: this.config.keyPair.publicKeyEncoding.type
        })*/
        try {
            this.privateKeyObject = native_crypto.createPrivateKey({
                key: this.privateKeyString,
                format: this.config.keyPair.privateKeyEncoding.format,
                type: this.config.keyPair.privateKeyEncoding.type,
                passphrase: this.passphrase
            })
            this.publicKeyObject = native_crypto.createPublicKey(this.privateKeyObject)
        } catch (e) {
            return false
        }
        return true
    }
    // Cryto.sign(str: string): string
    // Takes in a utf-8 formatted string and creates a SHA256 signature (base64 encoded) using the private key
    sign(str) {
        const sign = native_crypto.createSign("SHA256")
        sign.write(str)
        sign.end()
        return sign.sign(this.privateKeyObject, "base64")
    }
    // Crypto.encryptContentFor(content: string, publicKeyString: string): string
    // Takes in a utf-8 formatted string and encrypts it using a given public key string, returns base64 encoded string
    encryptContentFor(content, publicKeyString) {
        //const publicKeyObject = native_crypto.createPublicKey(publicKeyString)
        const buffer = Buffer.from(content)
        const encrypted_buffer = native_crypto.publicEncrypt(publicKeyString, buffer)
        return encrypted_buffer.toString("base64")
    }
    // Crypto.decryptContent(content: string)
    // Decrypts base64 encoded string to utf-8 encoded string using own private key object
    decryptContent(content) {
        const encrypted_buffer = Buffer.from(content, "base64")
        const buffer = native_crypto.privateDecrypt(this.privateKeyObject, encrypted_buffer)
        return buffer.toString()
    }
}

module.exports = Client
