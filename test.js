const sodi = require('./')
const assert = require('assert')

let sodi1 = sodi(sodi.generate())
let sodi2 = sodi(sodi.generate())

let msg = {test: Math.random()}
let msgString = JSON.stringify(msg)

let encrypted = sodi1.encrypt(msgString, sodi2.public)
let decrypted = sodi2.decrypt(encrypted.box, encrypted.nonce, sodi1.public)

assert.equal(JSON.parse(decrypted.toString()).test, msg.test)
console.log('encryption works')

let signature = sodi1.sign(msgString)
assert.ok(sodi2.verify(msgString, signature, sodi1.public))
console.log('signing works')
