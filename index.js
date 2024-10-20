const express = require("express");
const crypto = require("crypto");
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());

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

  privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKey, "base64"),
    type: "pkcs8",
    format: "der",
  });

  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  const signature = sign.sign(privateKey).toString("base64");

  res.send({ data, signature });
});

//Endpoint to verify
app.post("/verify", (req, res) => {
  let data = req.body.data;
  let publicKey = req.body.publicKey;
  let signature = req.body.signature;

  publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKey, "base64"),
    type: "spki",
    format: "der",
  });

  const verify = crypto.createVerify("SHA256");
  verify.update(data);
  verify.end();
  let result = verify.verify(publicKey, Buffer.from(signature, "base64"));
  res.send({ verify: result });
});

//base route
app.get("/", (req, res) => {
  res.send("Digital signature server is running");
});

// start server
app.listen(port, () => {
  console.log(`Digital signature server is running on port: ${port}`);
});
