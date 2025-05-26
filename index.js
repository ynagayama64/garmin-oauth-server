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

  // Garminでは oauth_verifier はヘッダーではなくURLに含めると安定
  const urlWithVerifier = `${requestData.url}?oauth_verifier=${oauth_verifier}&oauth_token=${oauth_token}`;

  try {
    const response = await axios.post(urlWithVerifier, null, { headers });
    const params = new URLSearchParams(response.data);
    const userId = params.get("userID") || params.get("user_id");

    if (userId) {
      await axios.post(webhookURL, { userId });
    }

    res.send(`<h2>Garmin 認証が完了しました</h2><p>userId: <strong>${userId}</strong></p>`);
  } catch (error) {
    console.error("Access Token Error:", error.response?.data || error.message);
    res.status(500).send("OAuth access_token failed: " + error.message);
  }
});
