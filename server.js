
const express = require("express");
const admin = require("firebase-admin");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const AYET_API_KEY = process.env.AYET_PUBLISHER_API_KEY;
const POINTS_MULTIPLIER = Number(
  process.env.AYET_POINTS_MULTIPLIER || 1
);

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Firebase service account is missing");
}

if (!AYET_API_KEY) {
  throw new Error("AYET_PUBLISHER_API_KEY is missing");
}

if (!Number.isFinite(POINTS_MULTIPLIER) || POINTS_MULTIPLIER <= 0) {
  throw new Error("Invalid AYET_POINTS_MULTIPLIER");
}

const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ------------------------------
// HEALTH CHECK
// ------------------------------

app.get("/", (req, res) => {
  res.status(200).send("MyContest Backend is running");
});

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

// ------------------------------
// CREATE / GET OFFERWALL USER ID
// Firebase Auth token required
// ------------------------------

app.post("/offerwall/user-id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const idToken = authHeader.substring(7);
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;

    const userRef = db.collection("users").doc(uid);

    const result = await db.runTransaction(async (transaction) => {
      const userSnapshot = await transaction.get(userRef);

      if (!userSnapshot.exists) {
        throw new Error("USER_NOT_FOUND");
      }

      const existingId = userSnapshot.get("offerwallUserId");

      if (existingId) {
        return existingId;
      }

      const newId = "MCW" + crypto.randomBytes(18).toString("hex");
      const mappingRef = db.collection("offerwall_users").doc(newId);

      transaction.set(mappingRef, {
        uid: uid,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      transaction.update(userRef, {
        offerwallUserId: newId,
      });

      return newId;
    });

    return res.status(200).json({
      success: true,
      offerwallUserId: result,
    });
  } catch (error) {
    console.error("Offerwall ID error:", error.message);

    if (error.message === "USER_NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Unable to create Offerwall ID",
    });
  }
});

// ------------------------------
// AYET HMAC VERIFICATION
// ------------------------------

function verifyAyetSignature(req) {
  const receivedHash =
    req.get("X-Ayetstudios-Security-Hash");

  if (!receivedHash) return false;

  const queryString = req.originalUrl.split("?")[1] || "";
  const params = new URLSearchParams(queryString);

  const sortedEntries = [...params.entries()].sort(
    ([keyA], [keyB]) => {
      if (keyA < keyB) return -1;
      if (keyA > keyB) return 1;
      return 0;
    }
  );

  const sortedParams = new URLSearchParams(sortedEntries);
  const sortedQueryString = sortedParams.toString();

  const calculatedHash = crypto
    .createHmac("sha256", AYET_API_KEY)
    .update(sortedQueryString)
    .digest("hex");

  const received = Buffer.from(receivedHash, "hex");
  const calculated = Buffer.from(calculatedHash, "hex");

  if (
    received.length !== calculated.length ||
    received.length !== 32
  ) {
    return false;
  }

  return crypto.timingSafeEqual(received, calculated);
}

// ------------------------------
// AYET CALLBACK
// GET REQUEST
// ------------------------------

app.get("/ayet/callback", async (req, res) => {
  try {
    // Verify ayeT security hash
    if (!verifyAyetSignature(req)) {
      console.warn("Invalid ayeT callback signature");

      return res.status(200).send("invalid");
    }

    const data = req.query;

    const callbackType = String(data.callback_type || "");
    const transactionId = String(data.transaction_id || "");
    const externalId = String(data.external_identifier || "");
    const currencyAmount = Number(data.currency_amount);
    const offerName = String(data.offer_name || "");
    const offerId = String(data.offer_id || "");
    const isChargeback = String(data.is_chargeback || "") === "1";

    // Only paid conversions and chargebacks are processed.
    if (
      callbackType !== "conversion" &&
      callbackType !== "chargeback"
    ) {
      return res.status(200).send("ignored");
    }

    if (
      !transactionId ||
      !externalId ||
      !Number.isFinite(currencyAmount) ||
      currencyAmount === 0 ||
      transactionId.length > 200 ||
      externalId.length > 200
    ) {
      return res.status(200).send("invalid parameters");
    }

    if (
      (callbackType === "chargeback" && !isChargeback) ||
      (callbackType === "conversion" && isChargeback)
    ) {
      return res.status(200).send("invalid callback type");
    }

    if (
      (callbackType === "conversion" && currencyAmount < 0) ||
      (callbackType === "chargeback" && currencyAmount > 0)
    ) {
      return res.status(200).send("invalid amount");
    }

    const points = Math.round(
      currencyAmount * POINTS_MULTIPLIER
    );

    if (!Number.isSafeInteger(points) || points === 0) {
      return res.status(200).send("invalid points");
    }

    // Find Firebase UID from Offerwall ID.
    const mappingRef = db
      .collection("offerwall_users")
      .doc(externalId);

    const mappingSnapshot = await mappingRef.get();

    if (!mappingSnapshot.exists) {
      console.warn("Unknown Offerwall user:", externalId);
      return res.status(200).send("unknown user");
    }

    const uid = mappingSnapshot.get("uid");

    if (!uid) {
      return res.status(200).send("invalid user mapping");
    }

    const userRef = db.collection("users").doc(uid);

    // Stable transaction document ID.
    const documentId = crypto
      .createHash("sha256")
      .update("ayet:" + transactionId)
      .digest("hex");

    const offerRef = db.collection("offerwall").doc(documentId);

    await db.runTransaction(async (transaction) => {
      const offerSnapshot = await transaction.get(offerRef);
      const userSnapshot = await transaction.get(userRef);

      // Prevent duplicate callbacks.
      if (offerSnapshot.exists) {
        return;
      }

      if (!userSnapshot.exists) {
        throw new Error("USER_NOT_FOUND");
      }

      // Credit or reverse points atomically.
      transaction.update(userRef, {
        points: admin.firestore.FieldValue.increment(points),
        lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      });

      transaction.create(offerRef, {
        userId: uid,
        offerwallUserId: externalId,
        provider: "ayet",
        transactionId: transactionId,
        offerId: offerId,
        offerName: offerName,
        currencyAmount: currencyAmount,
        pointsCredited: points,
        callbackType: callbackType,
        status: callbackType === "chargeback"
          ? "reversed"
          : "credited",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    console.log("Ayet callback processed:", transactionId);

    return res.status(200).send("success");

  } catch (error) {
    console.error("Ayet callback error:", error.message);

    if (error.message === "USER_NOT_FOUND") {
      return res.status(200).send("unknown user");
    }

    // Temporary server/database errors should be retried.
    return res.status(500).send("server error");
  }
});

// ------------------------------
// START SERVER
// ------------------------------

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
