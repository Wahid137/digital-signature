const express = require("express");
const crypto = require("crypto");
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());

// Generate a random key for AES encryption
const AES_KEY = crypto.randomBytes(32); // 256 bits
const AES_IV = crypto.randomBytes(16); // 128 bits

// Encrypt function
function encrypt(data) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");
  return { encryptedData: encrypted, iv: AES_IV.toString("base64") };
}

// Decrypt function
function decrypt(encryptedData, iv) {
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    AES_KEY,
    Buffer.from(iv, "base64")
  );
  let decrypted = decipher.update(encryptedData, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Endpoint to generate RSA key pair
app.get("/generate-key-pair", (req, res) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });
  res.send({
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  });
});

// Endpoint to create signature
app.post("/sign", (req, res) => {
  let data = req.body.data;
  let privateKey = req.body.privateKey;

  // Encrypt the data
  const { encryptedData, iv } = encrypt(data);

  // Create the RSA private key
  privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKey, "base64"),
    type: "pkcs8",
    format: "der",
  });

  // Sign the encrypted data
  const sign = crypto.createSign("SHA256");
  sign.update(encryptedData);
  sign.end();
  const signature = sign.sign(privateKey).toString("base64");

  res.send({ encryptedData, signature, iv: iv });
});

// Endpoint to verify
app.post("/verify", (req, res) => {
  let encryptedData = req.body.encryptedData;
  let publicKey = req.body.publicKey;
  let signature = req.body.signature;
  let iv = req.body.iv;

  // Create the RSA public key
  publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKey, "base64"),
    type: "spki",
    format: "der",
  });

  // Verify the signature
  const verify = crypto.createVerify("SHA256");
  verify.update(encryptedData);
  verify.end();
  let result = verify.verify(publicKey, Buffer.from(signature, "base64"));

  // Decrypt the data (optional, if you want to return the decrypted data)
  const decryptedData = decrypt(encryptedData, iv);

  res.send({ verify: result, decryptedData });
});

// Base route
app.get("/", (req, res) => {
  res.send("Digital signature server is running");
});

// Start server
app.listen(port, () => {
  console.log(`Digital signature server is running on port: ${port}`);
});
