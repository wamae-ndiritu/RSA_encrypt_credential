const fs = require("fs");
const crypto = require("crypto");

const publicKey = fs.readFileSync("cert/ProductionCertificate.cer", "utf8");

const initiatorPassword = "1234567";

// Convert the password to a buffer (byte array)
const passwordBuffer = Buffer.from(initiatorPassword, "utf8");

// Load the M-Pesa public key
const publicKeyObj = crypto.createPublicKey({
  key: publicKey,
  format: "pem",
  type: "spki",
});

// Encrypt the password using the M-Pesa public key
const encryptedPassword = crypto.publicEncrypt(
  {
    key: publicKeyObj,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  },
  passwordBuffer
);

// Convert the encrypted password to a Base64 encoded string (security credential)
const securityCredential = encryptedPassword.toString("base64");

console.log("Security Credential:", securityCredential);
