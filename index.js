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
// このURLはGASをWebアプリとしてデプロイした際に取得したURLに置き換えてください。
const webhookURL = "https://script.google.com/macros/s/AKfycbzTfMKQCekvLOxfe6tNmL1c30bC3kpCSQaHVRZGsi2SWqKNh5jIJpQi-MUzzV5Y_v6vXw/exec";

// OAuth初期化
const oauth = OAuth({
  consumer: { key: CONSUMER_KEY, secret: CONSUMER_SECRET },
  signature_method: "HMAC-SHA1",
  hash_function(base_string, key) {
    return crypto.createHmac("sha1", key).update(base_string).digest("base64");
  },
});

// リクエストトークンシークレットを一時的に保存するストア (メモリ上)
// サーバーが再起動すると失われるため、本番環境では永続化が必要です
let requestTokenStore = {};

// Step 1: 認証スタート
app.get("/auth/start", async (req, res) => {
  const request_data = {
    // GarminのOAuth Request Tokenエンドポイント (connectapi.garmin.com に修正済み)
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
    // GarminのOAuth Access Tokenエンドポイント (connectapi.garmin.com に修正済み)
    url: "https://connectapi.garmin.com/oauth-service/oauth/access_token",
    method: "POST",
    data: { oauth_token, oauth_verifier },
  };

  const headers = oauth.toHeader(oauth.authorize(request_data, { key: oauth_token, secret: tokenSecret }));

  try {
    const response = await axios.post(request_data.url, null, { headers });
    
    // ★ここを追加：Garminからのアクセストークン応答データ全体をログに出力します。
    // この情報が、userIdがnullになる原因特定に役立ちます。
    console.log("Garmin Access Token Response Data:", response.data); 
    
    const params = new URLSearchParams(response.data);

    // 現状userIdがnullになる原因を探るため、response.dataの内容を確認します。
    // もしログで`encoded_user_id`以外のキー名が見つかれば、ここを修正します。
    const userId = params.get("encoded_user_id"); 
    const accessToken = params.get("oauth_token");
    const accessTokenSecret = params.get("oauth_token_secret");

    // リクエストトークンシークレットは使用済みなので削除
    delete requestTokenStore[oauth_token];

    // --- Webhook購読処理 ---
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
      // userIdがnullの場合は、Webhook購読を試みないようにする（エラーを防ぐため）
      if (userId) {
        await axios.post(subscriptionUrl, {}, { headers: subscriptionHeaders });
        console.log(`Webhook subscription success for userId: ${userId}`);
      } else {
        console.warn("Webhook subscription skipped: userId is null.");
      }
    } catch (subscriptionErr) {
      console.error("Webhook subscription failed:", subscriptionErr.response?.data || subscriptionErr.message);
      // Webhook購読の失敗は、認証フローを中断させないが、ログで把握する
    }

    // --- Google Apps Scriptにアクセストークン情報送信 ---
    await axios.post(webhookURL, {
      type: "oauth_completion", // GAS側でOAuth完了イベントと識別するためのフラグ
      userId, // nullの可能性があるが、そのままGASに送信してGAS側でログを確認
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
