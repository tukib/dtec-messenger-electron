const {ipcMain} = require("electron")
const native_crypto = require("crypto")
const WebSocket = require("ws")
const Store = require('electron-store')
const store = new Store()
const ObjectID = require("mongodb").ObjectID

class Client {
    constructor() {
        this.crypto = new Crypto()
        this.pingTimeout = 0
        this.connected = false
        this.username = ""
        this.webContents = false
        this.messageCache = {}
        this.outgoingMessages = []
        const outgoingMessagesStore = store.get("outgoingMessages")
        if (outgoingMessagesStore) this.outgoingMessages = outgoingMessagesStore
        this.config = {
            server_address: "ws://ssh.ubuntu-cx31-tukib.hetzner-cloud.tukib.org:8080"
        }
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

        // temp
        this.connectToServer()
    }
    onWindowLoad(win) {
        this.webContents = win.webContents
        if (store.get("key.generated")) {
            this.webContents.send("show-login")
        } else {
            this.webContents.send("show-register")
        }
        this.startup()
    }
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
        this.startup()
    }
    startup() {
        if (!this.webContents || !this.connected) return
        console.log("client ready")
    }
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
    send(cmd, data, sign=false) {
        data.t = Date.now()
        if (sign) data = [data, this.crypto.sign(JSON.stringify(data))]
        this.ws.send(cmd + " " + JSON.stringify(data))
    }
    register(data) {
        if (!store.get("key.generated")) {
            console.log(data.password)
            //console.log(this.hashString(data.password))
            this.crypto.passphrase = data.password
            this.crypto.generateKeyPair()
            console.log(this.crypto.publicKeyString)
            store.set("key.generated", true)
            store.set("key.publicKey", this.crypto.publicKeyString)
            store.set("key.privateKey", this.crypto.privateKeyString)
        }
        this.send("register", {username: data.username, publicKeyString: this.crypto.publicKeyString}, true)
    }
    registerResponse(data) {
        if (data.ok) {
            this.login()
        } else {
            this.webContents.send("register-failed", data.username)
        }
    }
    login() {
        this.send("login", {publicKeyString: this.crypto.publicKeyString}, true)
    }
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
    postLogin() {
        this.send("get_hist", {as: this.username})
    }
    handleHistory(data) {
        // push locally stored messages to message array
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
    hashString(str) {
        const hash = native_crypto.createHash("sha256")
        hash.update(str)
        return hash.digest("hex")
    }
}

class Crypto {
    constructor() {
        this.passphrase = ""
        this.publicKeyString = ""
        this.privateKeyString = ""
        this.publicKeyObject = {}
        this.privateKeyObject = {}
        this.config = {
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
                }
            }
        }
        Object.defineProperty(this.config.keyPair.privateKeyEncoding, "passphrase", {
            get: () => this.passphrase
        })
    }
    generateKeyPair() {
        const keys = native_crypto.generateKeyPairSync("rsa", this.config.keyPair)
        this.publicKeyString = keys.publicKey
        this.privateKeyString = keys.privateKey
        this.loadKeys()
    }
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
    sign(str) {
        const sign = native_crypto.createSign("SHA256")
        sign.write(str)
        sign.end()
        return sign.sign(this.privateKeyObject, "hex")
    }
    encryptContentFor(content, publicKeyString) {
        //const publicKeyObject = native_crypto.createPublicKey(publicKeyString)
        const buffer = Buffer.from(content)
        const encrypted_buffer = native_crypto.publicEncrypt(publicKeyString, buffer)
        return encrypted_buffer.toString("base64")
    }
    decryptContent(content) {
        const encrypted_buffer = Buffer.from(content, "base64")
        const buffer = native_crypto.privateDecrypt(this.privateKeyObject, encrypted_buffer)
        return buffer.toString()
    }
}

module.exports = Client
