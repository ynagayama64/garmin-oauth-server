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

// リクエストトークンとシークレットを一時保存
let requestTokenStore = {};

// トップページ（初期表示）
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
    const params = new URLSearchParams(response.data);
    const token = params.get("oauth_token");
    const secret = params.get("oauth_token_secret");
    requestTokenStore[token] = secret;
    res.redirect(`https://connect.garmin.com/oauthConfirm?oauth_token=${token}`);
  } catch (error) {
    console.error("Request Token Error:", error.response?.data || error.message);
    res.status(500).send("OAuth request_token failed: " + error.message);
  }
});

// 認証コールバック
app.get("/auth/callback", async (req, res) => {
  const { oauth_token, oauth_verifier } = req.query;
  const tokenSecret = requestTokenStore[oauth_token];

  const requestData = {
    url: "https://connectapi.garmin.com/oauth-service/oauth/access_token",
    method: "POST",
  };

  const headers = oauth.toHeader(
    oauth.authorize(requestData, {
      key: oauth_token,
      secret: tokenSecret,
    })
  );

  // Garminでは oauth_verifier はURLに含めるのが安定
  const urlWithVerifier = `${requestData.url}?oauth_verifier=${oauth_verifier}&oauth_token=${oauth_token}`;

  try {
    const response = await axios.post(urlWithVerifier, null, { headers });
    console.log("Access Token Response:", response.data);
    const params = new URLSearchParams(response.data);
    const userId = params.get("userID") || params.get("user_id");

    // Google Apps Script へ userId を送信
    if (userId) {
      await axios.post(webhookURL, { userId });
    }

    res.send(`
      <h2>Garmin 認証が完了しました</h2>
      <p>userId: <strong>${userId || '（取得失敗）'}</strong></p>
    `);
  } catch (error) {
    console.error("Access Token Error:", error.response?.data || error.message);
    res.status(500).send("OAuth access_token failed: " + error.message);
  }
});

// サーバー起動
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
