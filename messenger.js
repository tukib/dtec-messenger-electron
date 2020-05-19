const {ipcMain} = require("electron")

class Client {
    constructor() {
        ipcMain.on("passSubmit", this.passSubmit)
    }
    passSubmit(event, pass) {
        console.log(pass)
    }
}

module.exports = Client
