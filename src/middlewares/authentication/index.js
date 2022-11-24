const dotenv = require("dotenv");
dotenv.config();
const {
	isAuthed,
	isExpiredAccessToken
} = require("../../services/authentication");

const isAuth = async (req, res, next) => {
	try {
		if (await isAuthed(req, res, next)) {
			if (await isExpiredAccessToken(req)) {
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
