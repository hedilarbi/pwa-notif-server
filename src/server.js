require("dotenv").config();

const express = require("express");
const cors = require("cors");
const webpush = require("web-push");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth.routes");
const pushRoutes = require("./routes/push.routes");
const connectionsRoutes = require("./routes/connections.routes");

const requiredEnvVars = [
  "MONGO_URI",
  "JWT_SECRET",
  "VAPID_PUBLIC_KEY",
  "VAPID_PRIVATE_KEY",
  "VAPID_EMAIL",
  "CONNECTION_ENCRYPTION_KEY",
];
const missing = requiredEnvVars.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.error(`Missing required environment variables: ${missing.join(", ")}`);
  console.error("Copy backend/.env.example to backend/.env and fill in the values.");
  process.exit(1);
}

webpush.setVapidDetails(
  process.env.VAPID_EMAIL,
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api/push", pushRoutes);
app.use("/api/connections", connectionsRoutes);

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 5000;

connectDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("Failed to connect to MongoDB", err);
    process.exit(1);
  });
