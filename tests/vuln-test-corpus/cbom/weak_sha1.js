// Short identifier derived from the manifest contents.
const crypto = require("crypto");

function manifestId(contents) {
  return crypto.createHash("sha1").update(contents).digest("hex");
}

module.exports = { manifestId };
