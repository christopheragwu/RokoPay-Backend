const jwt = require("jsonwebtoken");

exports.identifier = (req, res, next) => {
    let token;

    if (req.headers.client === "not-browser") {
        token = req.headers.authorization; // "Bearer <token>"
    } else {
        token = req.cookies["Authorization"]; // ✅ match case
    }

    if (!token) {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    try {
        let userToken = token;
        if (token.startsWith("Bearer ")) {
            userToken = token.split(" ")[1]; // get only the token
        }

        const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);

        req.user = jwtVerified; // attach decoded payload to request
        next();

    } catch (error) {
        console.error(error);
        return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }
};
