const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const SibApiV3Sdk = require("@sendinblue/client");
const { body, validationResult } = require("express-validator");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const axios = require("axios"); // Import axios for reCAPTCHA verification

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Sendinblue Client
const sendinblueClient = new SibApiV3Sdk.TransactionalEmailsApi();
sendinblueClient.setApiKey(
  SibApiV3Sdk.TransactionalEmailsApiApiKeys.apiKey,
  process.env.SENDINBLUE_API_KEY
);

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: "POST,GET",
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting to prevent brute force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.get("/", (req, res) => {
  res.send("Server is running at URL_ADDRESS:3000");
});

// reCAPTCHA Verification Route
app.options("/verify-recaptcha", cors()); // Enable pre-flight request for this endpoint
app.post("/verify-recaptcha", async (req, res) => {
  try {
    const { token } = req.body;
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify`,
      null,
      {
        params: {
          secret: secretKey,
          response: token,
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error("reCAPTCHA verification error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// API Endpoint for Sending OTP
app.post(
  "/send-otp",
  [
    body("phone")
      .trim()
      .matches(/^[0-9]{10}$/)
      .withMessage("Phone number must be 10 digits")
      .escape(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { phone } = req.body;
    const otp = crypto.randomInt(100000, 999999).toString();

    console.log(`OTP for ${phone}: ${otp}`);

    app.locals.otps = app.locals.otps || {};
    app.locals.otps[phone] = otp;

    res.status(200).json({ message: "OTP sent successfully!" });
  }
);

// API Endpoint for Verifying OTP
app.post(
  "/verify-otp",
  [
    body("phone")
      .trim()
      .matches(/^[0-9]{10}$/)
      .withMessage("Phone number must be 10 digits")
      .escape(),
    body("otp")
      .trim()
      .matches(/^[0-9]{6}$/)
      .withMessage("OTP must be 6 digits")
      .escape(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { phone, otp } = req.body;

    if (app.locals.otps && app.locals.otps[phone] === otp) {
      delete app.locals.otps[phone];
      res.status(200).json({ message: "OTP verified successfully!" });
    } else {
      res.status(400).json({ error: "Invalid OTP" });
    }
  }
);

// API Endpoint for Form Submission
app.post(
  "/submit-form",
  [
    body("fullName").trim().isLength({ min: 3 }).escape(),
    body("phone")
      .trim()
      .matches(/^[0-9]{10}$/)
      .withMessage("Phone number must be 10 digits")
      .escape(),
    body("email").isEmail().normalizeEmail().escape(),
    body("state").trim().escape(),
    body("campus").trim().escape(),
    body("course").trim().escape(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, phone, email, state, campus, course } = req.body;

    const sendSmtpEmail = {
      to: [{ email: "developer@ctgroup.in" }], // Send to developer's email
      sender: { email: "madhavarora132005@gmail.com" }, // Your verified sender email
      subject: "New Enquiry Form Submission",
      htmlContent: `
      <h2>New Enquiry Received</h2>
      <p><strong>Name:</strong> ${fullName}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Phone:</strong> ${phone}</p>
      <p><strong>State:</strong> ${state}</p>
      <p><strong>Campus:</strong> ${campus}</p>
      <p><strong>Course:</strong> ${course}</p>
    `,
    };

    try {
      await sendinblueClient.sendTransacEmail(sendSmtpEmail);
      res
        .status(200)
        .json({ message: "Form data sent to developer successfully!" });
    } catch (error) {
      console.error("Error sending email:", error.message);
      res
        .status(500)
        .json({ error: "Failed to send email", details: error.message });
    }
  }
);

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
