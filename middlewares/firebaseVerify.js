const admin = require("firebase-admin");

// ✅ Initialize Firebase Admin using .env credentials
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      type: process.env.FB_TYPE,
      project_id: process.env.FB_PROJECT_ID,
      private_key_id: process.env.FB_PRIVATE_KEY_ID,
      private_key: process.env.FB_PRIVATE_KEY.replace(/\\n/g, "\n"),
      client_email: process.env.FB_CLIENT_EMAIL,
      client_id: process.env.FB_CLIENT_ID,
      auth_uri: process.env.FB_AUTH_URI,
      token_uri: process.env.FB_TOKEN_URI,
      auth_provider_x509_cert_url: process.env.FB_AUTH_PROVIDER_CERT_URL,
      client_x509_cert_url: process.env.FB_CLIENT_CERT_URL,
    }),
  });
}

/**
 * Middleware: Verify Firebase ID Token
 */
exports.verifyFirebaseToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Missing or invalid token" });
    }

    const token = authHeader.split(" ")[1];

    // ✅ Verify ID token via Firebase Admin
    const decoded = await admin.auth().verifyIdToken(token);

    // ✅ Attach user info to request
    req.firebaseUser = decoded;
    next();
  } catch (err) {
    console.error("❌ Firebase token verification failed:", err);
    res.status(401).json({ message: "Unauthorized" });
  }
};
