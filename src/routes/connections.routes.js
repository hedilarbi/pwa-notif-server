const express = require("express");
const crypto = require("crypto");
const QRCode = require("qrcode");
const User = require("../models/User");
const PendingPairing = require("../models/PendingPairing");
const auth = require("../middleware/auth");
const { encrypt, decrypt } = require("../utils/crypto");
const { findConnectionByToken } = require("../utils/connectionAuth");

const router = express.Router();

const ALLOWED_PLATFORMS = ["prestashop", "woocommerce", "shopify"];

function hashSecret(secret) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

function secretsMatch(providedSecret, storedHash) {
  if (!providedSecret) return false;
  const providedHash = Buffer.from(hashSecret(providedSecret));
  const stored = Buffer.from(storedHash);
  return providedHash.length === stored.length && crypto.timingSafeEqual(providedHash, stored);
}

function buildPairingUrl(pairing, secret) {
  const params = new URLSearchParams({
    installationId: pairing.installationId,
    secret,
    platform: pairing.platform,
    siteName: pairing.siteName,
    siteUrl: pairing.siteUrl,
  });
  return `${process.env.FRONTEND_URL}/link?${params.toString()}`;
}

// Called by the platform module (e.g. PrestaShop) to start a pairing.
router.post("/pairings", async (req, res) => {
  try {
    const { platform, siteName, siteUrl, apiUrl } = req.body;
    if (!platform || !ALLOWED_PLATFORMS.includes(platform)) {
      return res.status(400).json({ message: "Invalid or missing platform" });
    }
    if (!siteName || !siteUrl) {
      return res.status(400).json({ message: "siteName and siteUrl are required" });
    }

    const installationId = crypto.randomUUID();
    const pairingSecret = crypto.randomBytes(24).toString("base64url");

    const pairing = await PendingPairing.create({
      installationId,
      pairingSecretHash: hashSecret(pairingSecret),
      platform,
      siteName,
      siteUrl,
      moduleApiUrl: apiUrl,
    });

    res.status(201).json({
      installationId,
      pairingSecret,
      pairingUrl: buildPairingUrl(pairing, pairingSecret),
      expiresInSeconds: 600,
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to create pairing", error: err.message });
  }
});

// Scannable QR image (SVG) encoding the pairing URL.
router.get("/pairings/:installationId/qr", async (req, res) => {
  try {
    const { secret } = req.query;
    const pairing = await PendingPairing.findOne({ installationId: req.params.installationId });
    if (!pairing || !secretsMatch(secret, pairing.pairingSecretHash)) {
      return res.status(404).json({ message: "Pairing not found" });
    }

    const svg = await QRCode.toString(buildPairingUrl(pairing, secret), { type: "svg", margin: 1 });
    res.type("image/svg+xml").send(svg);
  } catch (err) {
    res.status(500).json({ message: "Failed to generate QR code", error: err.message });
  }
});

// Polled by the platform module while waiting for the user to scan and confirm.
router.get("/pairings/:installationId", async (req, res) => {
  try {
    const { secret } = req.query;
    const pairing = await PendingPairing.findOne({ installationId: req.params.installationId });
    if (!pairing || !secretsMatch(secret, pairing.pairingSecretHash)) {
      return res.status(404).json({ status: "not_found" });
    }

    if (pairing.status !== "linked") {
      return res.json({ status: "pending" });
    }

    const apiToken = decrypt(pairing.encryptedApiToken);
    await PendingPairing.deleteOne({ _id: pairing._id });

    res.json({ status: "linked", installationId: pairing.installationId, apiToken });
  } catch (err) {
    res.status(500).json({ message: "Polling failed", error: err.message });
  }
});

// Called by the PWA (authenticated) after the user scans the QR and confirms.
router.post("/link", auth, async (req, res) => {
  try {
    const { installationId, secret } = req.body;
    if (!installationId || !secret) {
      return res.status(400).json({ message: "installationId and secret are required" });
    }

    const pairing = await PendingPairing.findOne({ installationId });
    if (!pairing || !secretsMatch(secret, pairing.pairingSecretHash)) {
      return res.status(404).json({ message: "Pairing invalide ou expirée" });
    }
    if (pairing.status === "linked") {
      return res.status(409).json({ message: "Cette boutique a déjà été connectée" });
    }

    const apiToken = crypto.randomBytes(32).toString("base64url");
    const encryptedApiToken = encrypt(apiToken);

    const user = await User.findById(req.userId);
    user.connections.push({
      platform: pairing.platform,
      siteName: pairing.siteName,
      siteUrl: pairing.siteUrl,
      moduleApiUrl: pairing.moduleApiUrl,
      installationId,
      encryptedApiToken,
      active: true,
    });
    await user.save();

    const connection = user.connections[user.connections.length - 1];

    pairing.status = "linked";
    pairing.userId = user._id;
    pairing.connectionId = connection._id;
    pairing.encryptedApiToken = encryptedApiToken;
    await pairing.save();

    res.status(201).json({
      connection: {
        id: connection._id,
        platform: connection.platform,
        siteName: connection.siteName,
        siteUrl: connection.siteUrl,
        active: connection.active,
      },
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: "Cette installation est déjà liée à un compte" });
    }
    res.status(500).json({ message: "Liaison échouée", error: err.message });
  }
});

router.get("/", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("connections");
    const connections = user.connections.map((c) => ({
      id: c._id,
      platform: c.platform,
      siteName: c.siteName,
      siteUrl: c.siteUrl,
      active: c.active,
      createdAt: c.createdAt,
    }));
    res.json({ connections });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch connections", error: err.message });
  }
});

// Called by the platform module on uninstall, authenticated with its own
// installationId + apiToken (no user session available at that point).
router.delete("/by-installation/:installationId", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    const match = await findConnectionByToken(req.params.installationId, token);
    if (!match) {
      return res.status(401).json({ message: "Invalid installation credentials" });
    }

    const { user, connection } = match;
    connection.deleteOne();
    await user.save();

    res.json({ message: "Connexion supprimée" });
  } catch (err) {
    res.status(500).json({ message: "Suppression échouée", error: err.message });
  }
});

router.delete("/:connectionId", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const connection = user.connections.id(req.params.connectionId);
    if (!connection) {
      return res.status(404).json({ message: "Connexion introuvable" });
    }
    connection.deleteOne();
    await user.save();
    res.json({ message: "Connexion supprimée" });
  } catch (err) {
    res.status(500).json({ message: "Suppression échouée", error: err.message });
  }
});

// Read-only order lookups, proxied through to the connected platform's own
// module/plugin API. Each platform exposes this differently, so the URL
// shape is built per platform here — the frontend only ever calls our own
// generic /:connectionId/orders[/:orderId] routes and stays unaware of
// the difference.
const PLATFORMS_WITH_ORDERS = ["prestashop", "woocommerce"];

function buildModuleApiUrl(connection, { action, orderId }) {
  const base = connection.moduleApiUrl.replace(/\/$/, "");
  const separator = base.includes("?") ? "&" : "?";

  if (connection.platform === "woocommerce") {
    // WordPress REST API: single route, order id as a query param (see
    // the plugin's register_rest_route for /orders). Query params are
    // used instead of a /orders/:id path segment because rest_url()
    // returns a "?rest_route=..." URL on sites without pretty permalinks,
    // which can't have a path segment appended after it.
    return action === "orders" ? base : `${base}${separator}id=${encodeURIComponent(orderId)}`;
  }

  // PrestaShop: query-string based front controller.
  const params = action === "orders" ? "action=orders" : `action=order&id=${encodeURIComponent(orderId)}`;
  return `${base}${separator}${params}`;
}

async function callModuleApi(connection, actionParams) {
  const apiToken = decrypt(connection.encryptedApiToken);
  const url = buildModuleApiUrl(connection, actionParams);

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "X-Pwanotifs-Token": apiToken,
    },
    signal: AbortSignal.timeout(10000),
  });

  return response;
}

async function getConnectionOrNotSupported(req, res) {
  const user = await User.findById(req.userId);
  const connection = user.connections.id(req.params.connectionId);
  if (!connection) {
    res.status(404).json({ message: "Connexion introuvable" });
    return null;
  }
  if (!PLATFORMS_WITH_ORDERS.includes(connection.platform)) {
    res.status(400).json({ message: "Plateforme non supportée pour les commandes" });
    return null;
  }
  if (!connection.moduleApiUrl) {
    res.status(409).json({ message: "Reconnectez cette boutique (scannez à nouveau le QR code) pour activer les commandes." });
    return null;
  }
  return connection;
}

router.get("/:connectionId/orders", auth, async (req, res) => {
  try {
    const connection = await getConnectionOrNotSupported(req, res);
    if (!connection) return;

    const response = await callModuleApi(connection, { action: "orders" });
    if (!response.ok) {
      return res.status(502).json({ message: "La boutique n'a pas pu être contactée", shopStatus: response.status });
    }

    res.json(await response.json());
  } catch (err) {
    res.status(500).json({ message: "Échec de récupération des commandes", error: err.message });
  }
});

router.get("/:connectionId/orders/:orderId", auth, async (req, res) => {
  try {
    const connection = await getConnectionOrNotSupported(req, res);
    if (!connection) return;

    const response = await callModuleApi(connection, { action: "order", orderId: req.params.orderId });
    if (response.status === 404) {
      return res.status(404).json({ message: "Commande introuvable" });
    }
    if (!response.ok) {
      return res.status(502).json({ message: "La boutique n'a pas pu être contactée", shopStatus: response.status });
    }

    res.json(await response.json());
  } catch (err) {
    res.status(500).json({ message: "Échec de récupération de la commande", error: err.message });
  }
});

module.exports = router;
