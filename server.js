
const express = require("express");
const admin = require("firebase-admin");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Firebase Admin connection
if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Firebase service account is missing");
}

const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// Backend health check
app.get("/", (req, res) => {
  res.status(200).send("MyContest Backend is running");
});

// Firebase connection check
app.get("/firebase-check", async (req, res) => {
  try {
    await db.collection("_backend_health").limit(1).get();
    res.status(200).json({
      success: true,
      message: "Firebase connected successfully",
    });
  } catch (error) {
    console.error("Firebase check failed:", error.message);
    res.status(500).json({ success: false });
  }
});

// ayet Studios callback - verification pending
app.post("/ayet/callback", async (req, res) => {
  res.status(501).json({
    success: false,
    message: "Callback verification is not configured yet",
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
