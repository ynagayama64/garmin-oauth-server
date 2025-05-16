const express = require("express");
const OAuth = require("oauth-1.0a");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3000;

const CONSUMER_KEY = process.env.CONSUMER_KEY;
const CONSUMER_SECRET = process.env.CONSUMER_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || "https://example.com/auth/callback";

const oauth = OAuth({
  consumer: { key: CONSUMER_KEY, secret: CONSUMER_SECRET },
  signature_method: "HMAC-SHA1",
  hash_function(base_string, key) {
    return crypto.createHmac("sha1", key).update(base_string).digest("base64");
  },
});

let requestTokenStore = {};

app.get("/auth/start", async (req, res) => {
  const requestData = {
    url: "https://connectapi.garmin.com/oauth-service/oauth/request_token",
    method: "POST",
    data: { oauth_callback: CALLBACK_URL },
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
    res.status(500).send("OAuth request_token failed: " + error.message);
  }
});

app.get("/auth/callback", async (req, res) => {
  const { oauth_token, oauth_verifier } = req.query;
  const tokenSecret = requestTokenStore[oauth_token];

  const requestData = {
    url: "https://connectapi.garmin.com/oauth-service/oauth/access_token",
    method: "POST",
    data: { oauth_token, oauth_verifier },
  };

  const headers = oauth.toHeader(
    oauth.authorize(requestData, {
      key: oauth_token,
      secret: tokenSecret,
    })
  );

  try {
    const response = await axios.post(requestData.url, null, { headers });
    const params = new URLSearchParams(response.data);
    const userId = params.get("userID");
    res.send(`<h2>Garmin 認証が完了しました</h2><p>userId: <strong>${userId}</strong></p>`);
  } catch (error) {
    res.status(500).send("OAuth access_token failed: " + error.message);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});