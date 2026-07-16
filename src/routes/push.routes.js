const express = require("express");
const crypto = require("crypto");
const webpush = require("web-push");
const PushSubscription = require("../models/PushSubscription");
const User = require("../models/User");
const auth = require("../middleware/auth");
const { decrypt } = require("../utils/crypto");

const router = express.Router();

router.post("/subscribe", auth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys || !keys.auth || !keys.p256dh) {
      return res.status(400).json({ message: "Invalid subscription payload" });
    }

    const subscription = await PushSubscription.findOneAndUpdate(
      { endpoint },
      { userId: req.userId, endpoint, keys },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    res.status(201).json({ subscription });
  } catch (err) {
    res.status(500).json({ message: "Subscription failed", error: err.message });
  }
});

router.delete("/unsubscribe", auth, async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) {
      return res.status(400).json({ message: "endpoint is required" });
    }

    await PushSubscription.deleteOne({ endpoint, userId: req.userId });
    res.json({ message: "Unsubscribed" });
  } catch (err) {
    res.status(500).json({ message: "Unsubscribe failed", error: err.message });
  }
});

router.post("/send", auth, async (req, res) => {
  try {
    const { title, body } = req.body;
    const subscriptions = await PushSubscription.find({ userId: req.userId });

    if (subscriptions.length === 0) {
      return res.status(404).json({ message: "No push subscriptions for this user" });
    }

    const result = await sendPush(subscriptions, title || "Notification", body || "Ceci est un test.");
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Send failed", error: err.message });
  }
});

router.post("/send-all", auth, async (req, res) => {
  try {
    const { title, body } = req.body;
    const subscriptions = await PushSubscription.find();

    if (subscriptions.length === 0) {
      return res.status(404).json({ message: "No push subscriptions found" });
    }

    const result = await sendPush(subscriptions, title || "Notification", body || "Notification broadcast.");
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Broadcast failed", error: err.message });
  }
});

// Called by a paired platform module (e.g. PrestaShop) to push a notification
// to the user behind a specific connection. Authenticated with the
// connection's own token instead of a user JWT, since the module has no
// user session.
router.post("/notify-connection", async (req, res) => {
  try {
    const installationId = req.header("X-Installation-Id");
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!installationId || !token) {
      return res.status(401).json({ message: "Missing installation credentials" });
    }

    const user = await User.findOne({ "connections.installationId": installationId });
    const connection = user?.connections.find((c) => c.installationId === installationId);
    if (!connection) {
      return res.status(401).json({ message: "Unknown installation" });
    }

    let expectedToken;
    try {
      expectedToken = decrypt(connection.encryptedApiToken);
    } catch {
      return res.status(500).json({ message: "Invalid stored credentials" });
    }

    const provided = Buffer.from(token);
    const expected = Buffer.from(expectedToken);
    const valid = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
    if (!valid || !connection.active) {
      return res.status(401).json({ message: "Invalid installation credentials" });
    }

    const { title, body } = req.body;
    const subscriptions = await PushSubscription.find({ userId: user._id });
    if (subscriptions.length === 0) {
      return res.status(404).json({ message: "No push subscriptions for this user" });
    }

    const result = await sendPush(subscriptions, title || `${connection.siteName}`, body || "");
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Send failed", error: err.message });
  }
});

async function sendPush(subscriptions, title, body) {
  const payload = JSON.stringify({ title, body });

  const results = await Promise.allSettled(
    subscriptions.map((sub) => webpush.sendNotification({ endpoint: sub.endpoint, keys: sub.keys }, payload))
  );

  await cleanupInvalidSubscriptions(subscriptions, results);

  return { sent: results.filter((r) => r.status === "fulfilled").length, total: results.length };
}

async function cleanupInvalidSubscriptions(subscriptions, results) {
  const staleIds = [];
  results.forEach((result, i) => {
    if (result.status === "rejected" && (result.reason.statusCode === 404 || result.reason.statusCode === 410)) {
      staleIds.push(subscriptions[i]._id);
    }
  });

  if (staleIds.length > 0) {
    await PushSubscription.deleteMany({ _id: { $in: staleIds } });
  }
}

module.exports = router;
