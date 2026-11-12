
const express = require("express");

const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;

// Server health check
app.get("/", (req, res) => {
  res.status(200).send("MyContest ayeT Backend is running");
});

// ayeT Studios callback endpoint
app.post("/ayet/callback", async (req, res) => {
  console.log("ayeT callback received");

  // Reward verification will be added
  // after confirming ayeT callback documentation.

  return res.status(501).json({
    success: false,
    message: "Callback verification not configured yet"
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
