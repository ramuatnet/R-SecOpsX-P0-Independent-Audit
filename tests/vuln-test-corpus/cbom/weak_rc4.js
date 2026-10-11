// Stream cipher used by the protocol adapter.
const { RC4 } = require("./vendor/stream");

function obfuscate(key, plaintext) {
  const cipher = new RC4(key);
  return cipher.process(plaintext);
}

module.exports = { obfuscate };
