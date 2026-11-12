
const express = require("express");
const admin = require("firebase-admin");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const AYET_API_KEY = process.env.AYET_PUBLISHER_API_KEY;

const EXPECTED_ADSLOT_ID = "31290";
const EXPECTED_PACKAGE = "com.vishal.mycontest";

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error("Firebase service account is missing");
}

if (!AYET_API_KEY) {
  throw new Error("AYET_PUBLISHER_API_KEY is missing");
}

const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

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
          const existingId = snapshot.get("offerwallUserId");

          if (existingId) {
            return existingId;
          }
        }

        const newId =
          "MCW" + crypto.randomBytes(18).toString("hex");

        transaction.set(
          offerwallRef,
          {
            offerwallUserId: newId,
            totalPoints: 0,
            totalEarnedPoints: 0,
            totalReversedPoints: 0,
            totalRevenueUsd: 0,
            totalReversedUsd: 0,
            netRevenueUsd: 0,
            createdAt: FieldValue.serverTimestamp(),
          },
          { merge: true }
        );

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
// HMAC SECURITY VERIFICATION
// --------------------------------

function verifyAyetSignature(req) {
  const receivedHash =
    req.get("X-Ayetstudios-Security-Hash") || "";

  if (!/^[a-fA-F0-9]{64}$/.test(receivedHash)) {
    return false;
  }

  const queryString = req.originalUrl.split("?")[1] || "";
  const params = new URLSearchParams(queryString);

  // Duplicate parameter names are not accepted.
  const entries = [...params.entries()];
  const names = entries.map(([key]) => key);

  if (new Set(names).size !== names.length) {
    return false;
  }

  // Alphabetically sort all callback parameters.
  entries.sort(([a], [b]) => {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  });

  const sortedQueryString =
    new URLSearchParams(entries).toString();

  const calculatedHash = crypto
    .createHmac("sha256", AYET_API_KEY)
    .update(sortedQueryString)
    .digest("hex");

  const received = Buffer.from(receivedHash, "hex");
  const calculated = Buffer.from(calculatedHash, "hex");

  return (
    received.length === calculated.length &&
    crypto.timingSafeEqual(received, calculated)
  );
}

// --------------------------------
// HELPERS
// --------------------------------

function makeTransactionId(provider, transactionId) {
  return crypto
    .createHash("sha256")
    .update(provider + ":" + transactionId)
    .digest("hex");
}

function parseUsdCents(value) {
  if (!/^-?\d+(\.\d{1,2})?$/.test(String(value))) {
    return null;
  }

  const negative = String(value).startsWith("-");
  const clean = String(value).replace("-", "");
  const parts = clean.split(".");

  const whole = Number(parts[0]);
  const decimal = Number(
    (parts[1] || "").padEnd(2, "0")
  );

  const cents = whole * 100 + decimal;

  if (!Number.isSafeInteger(cents)) {
    return null;
  }

  return negative ? -cents : cents;
}

function centsToUsd(cents) {
  return Number((cents / 100).toFixed(2));
}

// --------------------------------
// AYET CALLBACK
// --------------------------------

app.get("/ayet/callback", async (req, res) => {
  try {
    // 1. Verify HMAC first.
    if (!verifyAyetSignature(req)) {
      console.warn("Invalid ayeT signature");
      return res.status(403).send("Invalid signature");
    }

    const data = req.query;

    const callbackType = String(data.callback_type || "");
    const transactionId = String(data.transaction_id || "");
    const externalId = String(data.external_identifier || "");

    const currencyAmount = Number(data.currency_amount);
    const payoutCents = parseUsdCents(data.payout_usd);

    const offerName = String(data.offer_name || "");
    const offerId = String(data.offer_id || "");
    const placementId = String(data.placement_identifier || "");
    const adslotId = String(data.adslot_id || "");

    const isChargeback =
      String(data.is_chargeback || "") === "1" ||
      callbackType === "chargeback";

    // 2. Ignore non-paid callback types.
    if (
      callbackType &&
      callbackType !== "conversion" &&
      callbackType !== "chargeback"
    ) {
      return res.status(200).send("Ignored");
    }

    // 3. Validate callback data.
    if (
      !transactionId ||
      !externalId ||
      transactionId.length > 200 ||
      externalId.length > 200 ||
      !Number.isFinite(currencyAmount) ||
      currencyAmount === 0 ||
      payoutCents === null ||
      payoutCents === 0
    ) {
      return res.status(400).send("Invalid parameters");
    }

    if (
      (!isChargeback &&
        (currencyAmount < 0 || payoutCents < 0)) ||
      (isChargeback &&
        (currencyAmount > 0 || payoutCents > 0))
    ) {
      return res.status(400).send("Invalid amount");
    }

    // 4. Verify chargeback transaction ID format.
    if (
      isChargeback &&
      !transactionId.startsWith("r-")
    ) {
      return res.status(400).send("Invalid reversal ID");
    }

    if (
      !isChargeback &&
      transactionId.startsWith("r-")
    ) {
      return res.status(400).send("Invalid conversion ID");
    }

    // 5. Verify AdSlot.
    if (
      adslotId &&
      adslotId !== EXPECTED_ADSLOT_ID
    ) {
      return res.status(400).send("Invalid AdSlot");
    }

    // 6. Validate integer user points.
    const absolutePoints = Math.abs(currencyAmount);

    if (
      !Number.isSafeInteger(absolutePoints) ||
      absolutePoints <= 0
    ) {
      return res.status(400).send("Invalid points");
    }

    // The AdSlot conversion rate already calculates
    // the user's 50% reward. Do not divide again.
    const points = isChargeback
      ? -absolutePoints
      : absolutePoints;

    // 7. Find Offerwall user by external_identifier.
    const userQuery = await db
      .collection("offerwall")
      .where("offerwallUserId", "==", externalId)
      .limit(2)
      .get();

    if (userQuery.size !== 1) {
      console.warn("Unknown Offerwall ID");
      return res.status(200).send("Unknown user");
    }

    const offerwallRef = userQuery.docs[0].ref;
    const uid = offerwallRef.id;

    const transactionsRef =
      offerwallRef.collection("transactions");

    // 8. Get original transaction ID.
    const originalTransactionId = isChargeback
      ? transactionId.substring(2)
      : transactionId;

    if (!originalTransactionId) {
      return res.status(400).send("Invalid original ID");
    }

    const currentDocId = makeTransactionId(
      "ayet",
      transactionId
    );

    const originalDocId = makeTransactionId(
      "ayet",
      originalTransactionId
    );

    const reversalDocId = makeTransactionId(
      "ayet",
      "r-" + originalTransactionId
    );

    const currentRef = transactionsRef.doc(currentDocId);
    const originalRef = transactionsRef.doc(originalDocId);
    const reversalRef = transactionsRef.doc(reversalDocId);

    const revenueUsd = Math.abs(payoutCents);

    // 9. Atomic transaction.
    await db.runTransaction(async (transaction) => {
      const currentSnapshot =
        await transaction.get(currentRef);

      if (currentSnapshot.exists) {
        return;
      }

      const userSnapshot =
        await transaction.get(offerwallRef);

      if (!userSnapshot.exists) {
        throw new Error("OFFERWALL_USER_NOT_FOUND");
      }

      if (isChargeback) {
        const originalSnapshot =
          await transaction.get(originalRef);

        // Record reversal even if original arrives later.
        transaction.create(currentRef, {
          userId: uid,
          provider: "ayet",
          transactionId,
          originalTransactionId,
          offerId,
          offerName,
          placementId,
          adslotId,
          currencyAmount,
          payoutUsd: centsToUsd(-revenueUsd),
          points: 0,
          status: originalSnapshot.exists
            ? "reversed"
            : "reversal_pending",
          callbackType: "chargeback",
          createdAt: FieldValue.serverTimestamp(),
        });

        if (
          originalSnapshot.exists &&
          originalSnapshot.get("status") === "credited"
        ) {
          const originalPoints =
            originalSnapshot.get("points");

          const originalPayoutCents =
            parseUsdCents(
              String(originalSnapshot.get("payoutUsd"))
            );

          if (
            !Number.isSafeInteger(originalPoints) ||
            originalPoints <= 0 ||
            originalPayoutCents === null
          ) {
            throw new Error("INVALID_ORIGINAL_TRANSACTION");
          }

          transaction.update(originalRef, {
            status: "reversed",
            reversedAt: FieldValue.serverTimestamp(),
          });

          transaction.update(offerwallRef, {
            totalPoints:
              FieldValue.increment(-originalPoints),

            totalReversedPoints:
              FieldValue.increment(originalPoints),

            totalReversedUsd:
              FieldValue.increment(
                centsToUsd(originalPayoutCents)
              ),

            netRevenueUsd:
              FieldValue.increment(
                centsToUsd(-originalPayoutCents)
              ),
          });
        }

        return;
      }

      // Conversion arrives after a reversal.
      const reversalSnapshot =
        await transaction.get(reversalRef);

      if (reversalSnapshot.exists) {
        transaction.create(currentRef, {
          userId: uid,
          provider: "ayet",
          transactionId,
          offerId,
          offerName,
          placementId,
          adslotId,
          currencyAmount,
          payoutUsd: centsToUsd(revenueUsd),
          points: 0,
          status: "reversed",
          callbackType: "conversion",
          createdAt: FieldValue.serverTimestamp(),
        });

        transaction.update(reversalRef, {
          status: "reversed",
        });

        return;
      }

      // Normal conversion.
      transaction.create(currentRef, {
        userId: uid,
        provider: "ayet",
        transactionId,
        offerId,
        offerName,
        placementId,
        adslotId,
        currencyAmount,
        payoutUsd: centsToUsd(revenueUsd),
        points,
        status: "credited",
        callbackType: "conversion",
        createdAt: FieldValue.serverTimestamp(),
      });

      transaction.update(offerwallRef, {
        totalPoints: FieldValue.increment(points),

        totalEarnedPoints:
          FieldValue.increment(points),

        totalRevenueUsd:
          FieldValue.increment(centsToUsd(revenueUsd)),

        netRevenueUsd:
          FieldValue.increment(centsToUsd(revenueUsd)),

        lastUpdated: FieldValue.serverTimestamp(),
      });
    });

    console.log(
      "ayeT callback processed:",
      transactionId
    );

    return res.status(200).send("success");

  } catch (error) {
    console.error("ayeT callback error:", error.message);

    if (error.message === "OFFERWALL_USER_NOT_FOUND") {
      return res.status(200).send("Unknown user");
    }

    return res.status(500).send("Server error");
  }
});

// --------------------------------
// SERVER START
// --------------------------------

app.listen(PORT, () => {
  console.log(
    `MyContest Backend running on port ${PORT}`
  );
});
      
