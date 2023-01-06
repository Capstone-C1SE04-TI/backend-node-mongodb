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
	getUserByUsername,
	saveAccessTokensToDB
} = require("../services/crud-database/user");
const { cryptPassword, comparePassword } = require("../helpers");
const {
	isAuthed,
	generateAccessToken,
	generateRefreshAccessToken,
	handleRefreshAccessToken
} = require("../services/authentication");

const TI_AUTH_COOKIE = process.env.TI_AUTH_COOKIE;

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
				async (error, isPasswordMatch) => {
					if (isPasswordMatch) {
						const user = await getUserByUsername(username);

						if (!user.accessToken) {
							const accessToken = await generateAccessToken({
								username
							});
							const refreshAccessToken =
								await generateRefreshAccessToken({
									username
								});

							await saveAccessTokensToDB(
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
						} else {
							const { message } = await isAuthed(req);

							switch (message) {
								case "failed-unauthorized": {
									return res.status(200).json({
										message: message,
										error: message
									});
								}
								case "failed-expired-token": {
									return res.status(200).json({
										message: message,
										error: message
									});
								}
								case "successfully": {
									return res.status(200).json({
										message: message,
										error: null,
										user: {
											role: "user",
											username: user.username,
											userId: user.userId,
											email: user.email
										}
									});
								}
							}
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
			res.clearCookie(TI_AUTH_COOKIE);

			return res
				.status(200)
				.json({ message: "successfully", error: null });
		} catch (error) {
			return res.status(400).json({ message: "failed", error: error });
		}
	};

	this.refreshAccessToken = async (req, res, next) => {
		try {
			const { accessToken, refreshAccessToken } =
				await handleRefreshAccessToken(req);

			if (accessToken && refreshAccessToken) {
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
