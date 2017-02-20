const encryption = require('sodium-encryption')
const signatures = require('sodium-signatures')
const ed2curve = require('ed2curve')

const convertPublic = ed2curve.convertPublicKey
const convertPrivate = ed2curve.convertSecretKey

const generate = () => signatures.keyPair()

module.exports = keypair => {
  if (typeof keypair.publicKey === 'string') {
    keypair.publicKey = new Buffer(keypair.publicKey, 'hex')
  }
  if (typeof keypair.secretKey === 'string') {
    keypair.secretKey = new Buffer(keypair.secretKey, 'hex')
  }
  let curveSecret = ed2curve.convertSecretKey(keypair.secretKey)

  let scalar = publicKey => {
    if (!Buffer.isBuffer(publicKey)) publicKey = new Buffer(publicKey, 'hex')
    return encryption.scalarMultiplication(
      curveSecret,
      ed2curve.convertPublicKey(publicKey)
    )
  }

  let exports = {}

  exports.scalar = scalar
  exports.encrypt = (message, publicKey) => {
    if (!Buffer.isBuffer(message)) {
      if (typeof message !== 'string') {
        throw new Error('Message must be buffer or string')
      }
      message = new Buffer(message)
    }
    if (!Buffer.isBuffer(publicKey)) publicKey = new Buffer(publicKey, 'hex')
    let nonce = encryption.nonce()
    let box = encryption.encrypt(message, nonce, scalar(publicKey))
    return {box, nonce}
  }
  exports.decrypt = (box, nonce, publicKey) => {
    if (!Buffer.isBuffer(publicKey)) publicKey = new Buffer(publicKey, 'hex')
    if (!Buffer.isBuffer(nonce)) nonce = new Buffer(nonce, 'hex')
    let message = encryption.decrypt(box, nonce, scalar(publicKey))
    return message
  }
  exports.sign = message => {
    if (!Buffer.isBuffer(message)) {
      if (typeof message !== 'string') {
        throw new Error('Message must be buffer or string')
      }
      message = new Buffer(message)
    }
    return signatures.sign(message, keypair.secretKey)
  }
  exports.verify = (message, signature, publicKey) => {
    if (!Buffer.isBuffer(message)) {
      if (typeof message !== 'string') {
        throw new Error('Message must be buffer or string')
      }
      message = new Buffer(message)
    }
    if (!Buffer.isBuffer(publicKey)) publicKey = new Buffer(publicKey, 'hex')
    return signatures.verify(message, signature, publicKey)
  }
  exports.public = keypair.publicKey.toString('hex')
  return exports
}
module.exports.generate = generate
