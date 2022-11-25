const dotenv = require("dotenv");
dotenv.config();
const {
	isAuthedUser,
	isExpiredUserAccessToken
} = require("../../services/authentication/user");
const {
	isAuthedAdmin,
	isExpiredAdminAccessToken
} = require("../../services/authentication/admin");

const isAuth = async (req, res, next) => {
	try {
		if (await isAuthedUser(req, res, next)) {
			if (await isExpiredUserAccessToken(req)) {
				return res.status(400).json({
					message: "access-token-expired",
					error: "access-token-expired"
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
		if (await isAuthedAdmin(req, res, next)) {
			if (await isExpiredAdminAccessToken(req)) {
				return res.status(400).json({
					message: "access-token-expired",
					error: "access-token-expired"
				});
			}
		} else {
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
