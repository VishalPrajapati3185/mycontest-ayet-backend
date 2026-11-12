
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

// --------------------------------
// HEALTH CHECK
// --------------------------------

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
    console.error("Firebase check:", error.message);
    res.status(500).json({ success: false });
  }
});

// --------------------------------
// OFFERWALL USER ID
// All Offerwall data stays in offerwall
// --------------------------------

app.post("/offerwall/user-id", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const token = authHeader.substring(7);
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    const offerwallRef = db.collection("offerwall").doc(uid);

    const offerwallUserId = await db.runTransaction(
      async (transaction) => {
        const snapshot = await transaction.get(offerwallRef);

        if (snapshot.exists) {
          return snapshot.get("offerwallUserId");
        }

        const newId =
          "MCW" + crypto.randomBytes(18).toString("hex");

        transaction.set(offerwallRef, {
          offerwallUserId: newId,
          totalPoints: 0,
          totalEarned: 0,
          totalReversed: 0,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        return newId;
      }
    );

    return res.status(200).json({
      success: true,
      offerwallUserId,
    });

  } catch (error) {
    console.error("Offerwall ID error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to create Offerwall ID",
    });
  }
});

// --------------------------------
// AYET SIGNATURE VERIFICATION
// --------------------------------

function verifyAyetSignature(req) {
  const receivedHash =
    req.get("X-Ayetstudios-Security-Hash") || "";

  if (!/^[a-fA-F0-9]{64}$/.test(receivedHash)) {
    return false;
  }

  const queryString = req.originalUrl.split("?")[1] || "";
  const params = new URLSearchParams(queryString);

  const sortedParams = new URLSearchParams(
    [...params.entries()].sort(([a], [b]) =>
      a.localeCompare(b)
    )
  );

  const calculatedHash = crypto
    .createHmac("sha256", AYET_API_KEY)
    .update(sortedParams.toString())
    .digest("hex");

  const received = Buffer.from(receivedHash, "hex");
  const calculated = Buffer.from(calculatedHash, "hex");

  return (
    received.length === calculated.length &&
    crypto.timingSafeEqual(received, calculated)
  );
}

// --------------------------------
// TRANSACTION DOCUMENT ID
// --------------------------------

function makeTransactionId(provider, transactionId) {
  return crypto
    .createHash("sha256")
    .update(provider + ":" + transactionId)
    .digest("hex");
}

// --------------------------------
// AYET CALLBACK
// --------------------------------

app.get("/ayet/callback", async (req, res) => {
  try {
    // Verify callback signature first.
    if (!verifyAyetSignature(req)) {
      console.warn("Invalid ayeT security hash");
      return res.status(200).send("invalid signature");
    }

    const data = req.query;

    const callbackType = String(data.callback_type || "");
    const transactionId = String(data.transaction_id || "");
    const externalId = String(data.external_identifier || "");
    const currencyAmount = Number(data.currency_amount);

    const offerName = String(data.offer_name || "");
    const offerId = String(data.offer_id || "");
    const payoutUsd = Number(data.payout_usd || 0);

    const isChargeback =
      callbackType === "chargeback" ||
      String(data.is_chargeback || "") === "1";

    // Ignore non-paid optional callbacks.
    if (
      callbackType &&
      callbackType !== "conversion" &&
      callbackType !== "chargeback"
    ) {
      return res.status(200).send("ignored");
    }

    if (
      !transactionId ||
      !externalId ||
      transactionId.length > 200 ||
      externalId.length > 200 ||
      !Number.isFinite(currencyAmount) ||
      currencyAmount === 0
    ) {
      return res.status(200).send("invalid parameters");
    }

    // Validate conversion / reversal amount.
    if (
      (!isChargeback && currencyAmount < 0) ||
      (isChargeback && currencyAmount > 0)
    ) {
      return res.status(200).send("invalid amount");
    }

    const points = Math.round(
      currencyAmount * POINTS_MULTIPLIER
    );

    if (!Number.isSafeInteger(points) || points === 0) {
      return res.status(200).send("invalid points");
    }

    // Find user ONLY inside offerwall collection.
    const userQuery = await db
      .collection("offerwall")
      .where("offerwallUserId", "==", externalId)
      .limit(2)
      .get();

    if (userQuery.empty || userQuery.size !== 1) {
      console.warn("Unknown or duplicate Offerwall ID");
      return res.status(200).send("unknown user");
    }

    const offerwallRef = userQuery.docs[0].ref;
    const uid = offerwallRef.id;

    const transactionsRef =
      offerwallRef.collection("transactions");

    const transactionDocId = makeTransactionId(
      "ayet",
      transactionId
    );

    const transactionRef =
      transactionsRef.doc(transactionDocId);

    // ayeT reversal transaction IDs start with r-.
    const originalTransactionId = isChargeback
      ? transactionId.replace(/^r-/, "")
      : transactionId;

    const originalRef = transactionsRef.doc(
      makeTransactionId("ayet", originalTransactionId)
    );

    const reversalRef = transactionsRef.doc(
      makeTransactionId("ayet", "r-" + originalTransactionId)
    );

    await db.runTransaction(async (transaction) => {
      const currentSnapshot = await transaction.get(transactionRef);

      // Duplicate callback protection.
      if (currentSnapshot.exists) {
        return;
      }

      const userSnapshot = await transaction.get(offerwallRef);

      if (!userSnapshot.exists) {
        throw new Error("OFFERWALL_USER_NOT_FOUND");
      }

      if (isChargeback) {
        const originalSnapshot = await transaction.get(originalRef);

        // Record reversal even if original callback has not arrived yet.
        transaction.create(transactionRef, {
          userId: uid,
          provider: "ayet",
          transactionId,
          originalTransactionId,
          offerName,
          offerId,
          currencyAmount,
          points: 0,
          payoutUsd,
          status: originalSnapshot.exists
            ? "reversed"
            : "reversal_pending",
          callbackType: "chargeback",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        if (
          originalSnapshot.exists &&
          originalSnapshot.get("status") === "credited"
        ) {
          transaction.update(originalRef, {
            status: "reversed",
            reversedAt:
              admin.firestore.FieldValue.serverTimestamp(),
          });

          transaction.update(offerwallRef, {
            totalPoints:
              admin.firestore.FieldValue.increment(points),
            totalReversed:
              admin.firestore.FieldValue.increment(Math.abs(points)),
          });
        }

        return;
      }

      // If reversal arrived first, do not credit the conversion.
      const reversalSnapshot = await transaction.get(reversalRef);

      if (reversalSnapshot.exists) {
        transaction.create(transactionRef, {
          userId: uid,
          provider: "ayet",
          transactionId,
          offerName,
          offerId,
          currencyAmount,
          points: 0,
          payoutUsd,
          status: "reversed",
          callbackType: "conversion",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        transaction.update(reversalRef, {
          status: "reversed",
        });

        return;
      }

      // Normal conversion.
      transaction.create(transactionRef, {
        userId: uid,
        provider: "ayet",
        transactionId,
        offerName,
        offerId,
        currencyAmount,
        points,
        payoutUsd,
        status: "credited",
        callbackType: "conversion",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      transaction.update(offerwallRef, {
        totalPoints:
          admin.firestore.FieldValue.increment(points),
        totalEarned:
          admin.firestore.FieldValue.increment(points),
      });
    });

    console.log("ayeT callback completed:", transactionId);

    return res.status(200).send("success");

  } catch (error) {
    console.error("ayeT callback error:", error.message);

    if (error.message === "OFFERWALL_USER_NOT_FOUND") {
      return res.status(200).send("unknown user");
    }

    return res.status(500).send("server error");
  }
});

// --------------------------------
// SERVER START
// --------------------------------

app.listen(PORT, () => {
  console.log(`MyContest Backend running on port ${PORT}`);
});
