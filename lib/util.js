var crypto = require('crypto')

function hmacSHA256 (v, k) {
  return crypto.createHmac('sha256', k).update(v).digest()
}

module.exports = {
  hmacSHA256: hmacSHA256
}
