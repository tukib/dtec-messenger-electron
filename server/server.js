"use strict"
const crypto = require("crypto")
const {MongoClient, ObjectID} = require("mongodb")
const mongoDBInfo = {
    url: "mongodb://127.0.0.1:27017",
    name: "dtec-messenger"
}
let db, USERS, MESSAGES
MongoClient.connect(mongoDBInfo.url, {useUnifiedTopology: true}, async (err, client) => {
    db = client.db(mongoDBInfo.name)
    USERS = db.collection("users")
    MESSAGES = db.collection("messages")
})

const WebSocket = require("ws")
const wss = new WebSocket.Server({port: 8080})
const send = (ws, cmd, data) => {
    ws.send(cmd + " " + JSON.stringify(data))
}
const verify = (publicKeyObject, str, signature) => {
    const verify = crypto.createVerify("SHA256")
    verify.write(str)
    verify.end()
    return verify.verify(publicKeyObject, signature, "hex")
}
wss.on("connection", async ws => {
    ws.isAlive = true
    ws.on("pong", () => ws.isAlive = true)
    ws.on("message", async msg => {
        console.log(msg)
        const cmd = msg.substr(0, msg.indexOf(" "))
        let data = JSON.parse(msg.substr(msg.indexOf(" ") + 1))
        let isPublicKeyVerified = false
        if (Array.isArray(data)) {
            const signature = data[1]
            data = data[0]
            const publicKeyObject = crypto.createPublicKey(data.publicKeyString)
            isPublicKeyVerified = verify(publicKeyObject, JSON.stringify(data), signature)
        }
        if (!data.t || data.t < Date.now() - 5000 || data.t > Date.now()) return
        if (cmd === "register") {
            if (!isPublicKeyVerified) return
            let existing_user = await USERS.findOne({_id: data.username})
            if (existing_user) return send(ws, "register_res", {ok: false, username: data.username})
            USERS.insertOne({_id: data.username, publicKeyString: data.publicKeyString})
            return send(ws, "register_res", {ok: true})
        } else if (cmd === "login") {
            if (!isPublicKeyVerified) return
            let user = await USERS.findOne({publicKeyString: data.publicKeyString})
            if (!user) return
            ws.username = user._id
            console.log("client logged in as " + ws.username)
            return send(ws, "login_res", {username: user._id})
        } else if (cmd === "whois") {
            let user = await USERS.findOne({_id: data.user})
            if (!user) return send (ws, "whois_res", {ok: false, forMessage: data.forMessage})
            return send(ws, "whois_res", {ok: true, publicKeyString: user.publicKeyString, forMessage: data.forMessage})
        }

        if (data.as !== ws.username) return

        if (cmd === "msg") {
            console.log("verified message from " + data.as + " to " + data.to)
            const message_obj = {
                _id: new ObjectID(data.id),
                to: data.to,
                from: data.as,
                content: data.content,
                time: data.t
            }
            const entry = await MESSAGES.insertOne(message_obj)
            if (entry.insertedCount !== 1) return send(ws, "msg_res", {ok: false, id: data.id})
            for (let _ws of wss.clients) {
                if (_ws.username === data.to) {
                    send(_ws, "new_msg", {message: message_obj})
                    break
                }
            }
            return send(ws, "msg_res", {ok: true, id: data.id, r_t: data.t})
        } else if (cmd === "get_hist") {
            const messages = await MESSAGES.find({to: data.as}).toArray()
            require("util").inspect(messages)
            return send(ws, "hist", {messages: messages})
        }
    })
})

const pingInterval = setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) return ws.terminate()
        ws.isAlive = false
        ws.ping()
    })
}, 10000)

wss.on("close", () => {
    clearInterval(pingInterval)
    console.log("stopped pinging: websocket server closed")
})