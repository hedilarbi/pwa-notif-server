const crypto = require("crypto");
const User = require("../models/User");
const { decrypt } = require("./crypto");

// Verifies a platform module's identity for a given connection using its
// installationId + apiToken (the module has no user session/JWT).
async function findConnectionByToken(installationId, token) {
  if (!installationId || !token) return null;

  const user = await User.findOne({ "connections.installationId": installationId });
  const connection = user?.connections.find((c) => c.installationId === installationId);
  if (!connection) return null;

  let expectedToken;
  try {
    expectedToken = decrypt(connection.encryptedApiToken);
  } catch {
    return null;
  }

  const provided = Buffer.from(token);
  const expected = Buffer.from(expectedToken);
  const valid = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);

  return valid ? { user, connection } : null;
}

module.exports = { findConnectionByToken };
