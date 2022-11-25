const dotenv = require("dotenv");
dotenv.config();

const {
	validateSignUpBody,
	validateSignInBody
} = require("../validators/user");
const {
	createNewUser,
	checkExistedUsername,
	checkExistedEmail,
	getPasswordByUsername,
	updateUserAuthorizationByUsername
} = require("../services/crud-database/user");
const {
	isAuthedUser,
	generateUserAccessToken,
	generateUserRefreshAccessToken,
	isExpiredUserAccessToken,
	handleRefreshUserAccessToken
} = require("../services/authentication/user");
const { cryptPassword, comparePassword } = require("../helpers");
const { UserModel } = require("../models");

function AuthController() {
	this.signup = async (req, res, next) => {
		const { username, email, phoneNumber, password } = req.body;
		const { status, error } = await validateSignUpBody(req, res, next);

		if (status === "failed")
			return res.status(400).json({ message: error, error: error });

		if (await checkExistedUsername(username))
			return res.status(400).json({
				message: "username-existed",
				error: "username-existed"
			});

		if (await checkExistedEmail(email))
			return res
				.status(400)
				.json({ message: "email-existed", error: "email-existed" });

		cryptPassword(password, async (error, hashPassword) =>
			(await createNewUser({
				username,
				email,
				phoneNumber,
				hashPassword
			})) == true
				? res.status(200).json({
						message: "successfully",
						error: null
				  })
				: res.status(400).json({
						message: "failed",
						error: error
				  })
		);
	};

	this.signin = async (req, res, next) => {
		const { username, password } = req.body;
		const { status, error } = await validateSignInBody(req, res, next);

		if (status === "failed")
			return res.status(400).json({
				message: error,
				error: error,
				user: null
			});

		if (!(await checkExistedUsername(username))) {
			return res.status(404).json({
				message: "username-notfound",
				error: "username-notfound",
				user: null
			});
		} else {
			const hashPassword = await getPasswordByUsername(username);
			comparePassword(
				password,
				hashPassword,
				async (error, passwordMatch) => {
					if (passwordMatch) {
						const user = await UserModel.findOne({
							username: username
						}).select("accessToken username userId email -_id");

						// First time signin
						if (user.accessToken === "") {
							const accessToken = await generateUserAccessToken({
								username: username
							});
							const refreshAccessToken =
								await generateUserRefreshAccessToken({
									username: username
								});

							await updateUserAuthorizationByUsername(
								username,
								accessToken,
								refreshAccessToken
							);

							return res.status(200).json({
								message: "successfully",
								error: null,
								user: {
									role: "user",
									username: user.username,
									userId: user.userId,
									email: user.email,
									accessToken: accessToken,
									refreshAccessToken: refreshAccessToken
								}
							});
						}

						// Not first time signin
						if (await isAuthedUser(req)) {
							if (await isExpiredUserAccessToken(req)) {
								return res.status(400).json({
									message: "failed-access-token-expired",
									error: "failed-access-token-expired",
									user: null
								});
							} else {
								return res.status(200).json({
									message: "successfully",
									error: null,
									user: {
										role: "user",
										username: user.username,
										userId: user.userId,
										email: user.email
									}
								});
							}
						} else {
							return res.status(400).json({
								message: "failed-unauthorized",
								error: "failed-unauthorized",
								user: null
							});
						}
					} else {
						return res.status(400).json({
							message: "incorrect-password",
							error: "incorrect-password",
							user: null
						});
					}
				}
			);
		}
	};

	this.signout = (req, res, next) => {
		try {
			req.user = null;
			req.session = null;

			return res
				.status(200)
				.json({ message: "successfully", error: null });
		} catch (error) {
			return res.status(400).json({ message: "failed", error: error });
		}
	};

	this.refreshAccessToken = async (req, res, next) => {
		try {
			const newTokens = await handleRefreshUserAccessToken(req);
			const { accessToken, refreshAccessToken } = newTokens;

			if (newTokens) {
				return res.status(200).json({
					message: "successfully",
					error: null,
					newAccessToken: accessToken,
					newRefreshAccessToken: refreshAccessToken
				});
			} else {
				return res.status(400).json({
					message: "failed",
					error: error,
					newAccessToken: null,
					newRefreshAccessToken: null
				});
			}
		} catch (error) {
			return res.status(400).json({
				message: "failed",
				error: error,
				newAccessToken: null,
				newRefreshAccessToken: null
			});
		}
	};
}

module.exports = new AuthController();
