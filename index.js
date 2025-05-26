const express = require("express");
const OAuth = require("oauth-1.0a");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3000;

const CONSUMER_KEY = process.env.CONSUMER_KEY;
const CONSUMER_SECRET = process.env.CONSUMER_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || "https://garmin-oauth-server.onrender.com/auth/callback";

// Garmin Webhook 受信先（Google Apps Script）
const webhookURL = "https://script.google.com/macros/s/AKfycbzTfMKQCekvLOxfe6tNmL1c30bC3kpCSQaHVRZGsi2SWqKNh5jIJpQi-MUzzV5Y_v6vXw/exec";

// OAuth 初期化
const oauth = OAuth({
  consumer: { key: CONSUMER_KEY, secret: CONSUMER_SECRET },
  signature_method: "HMAC-SHA1",
  hash_function(base_string, key) {
    return crypto.createHmac("sha1", key).update(base_string).digest("base64");
  },
});

// トップページ
app.get("/", (req, res) => {
  res.send(`
    <h1>Garmin OAuth Server is running.</h1>
    <p>Garminと連携するには <a href="/auth/start">/auth/start</a> をクリックしてください。</p>
  `);
});

// 認証開始
app.get("/auth/start", async (req, res) => {
  const requestData = {
    url: `https://connectapi.garmin.com/oauth-service/oauth/request_token?oauth_callback=${encodeURIComponent(CALLBACK_URL)}`,
    method: "POST",
  };

  const headers = oauth.toHeader(oauth.authorize(requestData));

  try {
    const response = await axios.post(requestData.url, null, { headers });

    // ✅ レスポンスのログ出力（Renderログで確認可能）
    console.log("=== Garmin request_token response ===");
    console.log(response.data);

    const params = new URLSearchParams(response.data);
    const token = params.get("oauth_token");
    const secret = params.get("oauth_token_secret");

    console.log("oauth_token:", token);
    console.log("oauth_token_secret:", secret);

    res.redirect(`https://connect.garmin.com/oauthConfirm?oauth_token=${token}&secret=${encodeURIComponent(secret)}`);
  } catch (error) {
    console.error("Request Token Error:", error.response?.data || error.message);
    res.status(500).send("OAuth request_token failed: " + error.me_
