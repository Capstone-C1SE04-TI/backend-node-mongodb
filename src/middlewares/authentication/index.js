const dotenv = require("dotenv");
dotenv.config();
const { isAuthed } = require("../../services/authentication");

const isAuth = async (req, res, next) => {
	try {
		if (await isAuthed(req, res, next)) {
			if (await isExpiredAccessToken(req)) {
				const newTokens = await handleRefreshAccessToken(req);

				if (!newTokens)
					return res.status(400).json({
						message: "failed-refresh-token",
						error: "failed-refresh-token"
					});
				else
					return res.status(200).json({
						message: "token-expired",
						error: "token-expired",
						newAccessToken: newTokens.accessToken,
						newRefreshAccessToken: newTokens.refreshAccessToken
					});
			}
		} else {
			return res.status(403).json({
				message: "access-denied unauthorized",
				error: "access-denied unauthorized"
			});
		}

		next();
	} catch (error) {
		return res.status(403).json({
			message: "access-denied unauthorized",
			error: "access-denied unauthorized"
		});
	}
};

const isAdmin = async (req, res, next) => {
	try {
		if (req.user.role !== "admin") {
			return res.status(403).json({
				message: "access-denied admin-resource",
				error: "access-denied admin-resource"
			});
		}
		next();
	} catch (e) {
		return res.status(403).json({
			message: "access-denied admin-resource",
			error: "access-denied admin-resource"
		});
	}
};

module.exports = {
	isAuth,
	isAdmin
};
