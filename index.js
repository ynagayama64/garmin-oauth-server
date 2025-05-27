const express = require("express");
const OAuth = require("oauth-1.0a");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3000;

const CONSUMER_KEY = process.env.CONSUMER_KEY;
const CONSUMER_SECRET = process.env.CONSUMER_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || "https://garmin-oauth-server.onrender.com/auth/callback";

// あなたのGoogle Apps ScriptのWebhook URL
const webhookURL = "https://script.google.com/macros/s/AKfycbzTfMKQCekvLOxfe6tNmL1c30bC3kpCSQaHVRZGsi2SWqKNh5jIJpQi-MUzzV5Y_v6vXw/exec"; // ★あなたのGAS WebアプリURLに置き換えてください

// OAuth初期化
const oauth = OAuth({
  consumer: { key: CONSUMER_KEY, secret: CONSUMER_SECRET },
  signature_method: "HMAC-SHA1",
  hash_function(base_string, key) {
    return crypto.createHmac("sha1", key).update(base_string).digest("base64");
  },
});

let requestTokenStore = {};

// Step 1: 認証スタート
app.get("/auth/start", async (req, res) => {
  const request_data = {
    // ★ ここを修正: GarminのOAuth Request Tokenエンドポイント
    url: "https://connectapi.garmin.com/oauth-service/oauth/request_token",
    method: "POST",
    data: { oauth_callback: CALLBACK_URL },
  };

  const headers = oauth.toHeader(oauth.authorize(request_data));

  try {
    const response = await axios.post(request_data.url, null, { headers });
    const params = new URLSearchParams(response.data);
    const oauth_token = params.get("oauth_token");
    const oauth_token_secret = params.get("oauth_token_secret");

    requestTokenStore[oauth_token] = oauth_token_secret;

    res.redirect(`https://connect.garmin.com/oauthConfirm?oauth_token=${oauth_token}`);
  } catch (error) {
    console.error("Error getting request token:", error.response?.data || error.message);
    res.status(500).send("Error getting request token: " + (error.response?.data ? JSON.stringify(error.response.data) : error.message));
  }
});

// Step 2: Garminからのコールバック処理 + Webhook購読 + GAS通知
app.get("/auth/callback", async (req, res) => {
  const { oauth_token, oauth_verifier } = req.query;
  const tokenSecret = requestTokenStore[oauth_token];

  if (!tokenSecret) {
    console.error("Invalid or expired oauth_token in callback. tokenSecret was not found.");
    return res.status(400).send("Invalid or expired oauth_token.");
  }

  const request_data = {
    // ★ ここを修正: GarminのOAuth Access Tokenエンドポイント
    url: "https://connectapi.garmin.com/oauth-service/oauth/access_token",
    method: "POST",
    data: { oauth_token, oauth_verifier },
  };

  const headers = oauth.toHeader(oauth.authorize(request_data, { key: oauth_token, secret: tokenSecret }));

  try {
    const response = await axios.post(request_data.url, null, { headers });
    const params = new URLSearchParams(response.data);

    const userId = params.get("encoded_user_id");
    const accessToken = params.get("oauth_token");
    const accessTokenSecret = params.get("oauth_token_secret");

    // リクエストトークンシークレットは使用済みなので削除
    delete requestTokenStore[oauth_token];

    // --- Webhook購読処理の追加 ---
    // Webhook SubscriptionのURLはHealth APIのドキュメントで別途確認が必要ですが、
    // 現在のところapi.garmin.comのままが一般的です。
    const subscriptionUrl = `https://api.garmin.com/wellness-api/rest/user/${userId}/webhook-subscription`;
    const subscriptionHeaders = oauth.toHeader(
      oauth.authorize(
        { url: subscriptionUrl, method: "POST" },
        { key: accessToken, secret: accessTokenSecret }
      )
    );

    try {
      await axios.post(subscriptionUrl, {}, { headers: subscriptionHeaders });
      console.log(`Webhook subscription success for userId: ${userId}`);
    } catch (subscriptionErr) {
      console.error("Webhook subscription failed:", subscriptionErr.response?.data || subscriptionErr.message);
      // Webhook購読の失敗は、認証フローを中断させないが、ログで把握する
    }

    // --- Google Apps Scriptにアクセストークン情報送信 ---
    await axios.post(webhookURL, {
      type: "oauth_completion", // GAS側でOAuth完了イベントと識別するためのフラグ
      userId,
      accessToken,
      accessTokenSecret,
    });

    res.send("Garmin認証が完了し、Webhook購読を行いました。");
  } catch (err) {
    console.error("Access token error:", err.response?.data || err.message);
    res.status(500).send("Access token error: " + (err.response?.data ? JSON.stringify(err.response.data) : err.message));
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
