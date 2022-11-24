const _ = require("lodash");
const { cryptPassword, comparePassword } = require("../helpers");

const {
	getUserByEmail,
	updateUserPassword,
	getPasswordByEmail,
	followWalletOfShark,
	unfollowWalletOfShark,
	getListOfSharkFollowed
} = require("../services/crud-database/user");
const {
	getUserProfile,
	updateUserProfile,
	upgradeUserPremiumAccount,
} = require("../services/crud-database/admin");
const {
	validateUpdateProfileBody,
	validateChangePasswordBody
} = require("../validators/user");

function UserController() {
	this.getUserProfile = async (req, res, next) => {
		let userId = req.query.userId;

		if (!userId) userId = null;
		else {
			const userIdCheck = _.toString(userId);
			if (_.isNaN(userIdCheck)) userId = undefined;
			else userId = Number(userIdCheck);
		}

		await getUserProfile(userId)
			.then((data) =>
				Object.entries(data).length === 0
					? res.status(400).json({
							message: "failed-userid-invalid",
							error: "userid-invalid",
							data: {}
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							data: data
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					data: {}
				})
			);
	};

	this.updateUserProfile = async (req, res, next) => {
		let userId = req.query.userId;

		if (!userId) userId = null;
		else {
			const userIdCheck = _.toString(userId);
			if (_.isNaN(userIdCheck)) userId = undefined;
			else userId = Number(userIdCheck);
		}

		const { status, error } = await validateUpdateProfileBody(
			req,
			res,
			next
		);

		if (status === "failed")
			return res.status(400).json({ message: error, error: error });
		else {
			const updateInfo = req.body;
			await updateUserProfile(userId, updateInfo)
				.then((data) =>
					data === "success"
						? res.status(200).json({
								message: "successfully",
								error: null
						  })
						: res.status(400).json({
								message: data,
								error: data
						  })
				)
				.catch((error) =>
					res.status(400).json({
						message: "failed",
						error: error
					})
				);
		}
	};

	this.changePassword = async (req, res, next) => {
		const { status, error } = await validateChangePasswordBody(
			req,
			res,
			next
		);

		if (status === "failed")
			return res.status(400).json({ message: error, error: error });
		else {
			const { email, oldPassword, newPassword } = req.body;
			const user = await getUserByEmail(email);

			if (user) {
				// Check correct old password
				const password = await getPasswordByEmail(email);
				comparePassword(
					oldPassword,
					password,
					(error, isPasswordMatch) => {
						if (isPasswordMatch) {
							cryptPassword(
								newPassword,
								async (error, hashPassword) =>
									(await updateUserPassword(
										user.userId,
										hashPassword
									)) === true
										? res.status(200).json({
												message: "successfully",
												error: null
										  })
										: res.status(400).json({
												message: "failed",
												error: error
										  })
							);
						} else {
							return res.status(400).json({
								message: "incorrect-oldpassword",
								error: "incorrect-oldpassword"
							});
						}
					}
				);
			} else {
				return res
					.status(400)
					.json({ message: "user-notfound", error: "user-notfound" });
			}
		}
	};

	this.upgradePremiumAccount = async (req, res, next) => {
		let userId = req.body.userId;

		if (!userId) userId = null;
		else {
			if (isNaN(userId)) userId = undefined;
			else userId = Number(userId);
		}

		await upgradeUserPremiumAccount(userId)
			.then((data) =>
				data === "success"
					? res.status(200).json({
							message: "successfully",
							error: null
					  })
					: res.status(400).json({
							message: data,
							error: data
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error
				})
			);
	};

	this.followSharkWallet = async (req, res, next) => {
		let { userId, sharkId } = req.body;

		if (!userId) userId = null;
		else {
			if (isNaN(userId)) userId = undefined;
			else userId = Number(userId);
		}

		if (!sharkId) sharkId = null;
		else {
			if (isNaN(sharkId)) sharkId = undefined;
			else sharkId = Number(sharkId);
		}

		await followWalletOfShark(userId, sharkId)
			.then((data) => {
				if (data === "success")
					return res.status(200).json({
						message: "successfully",
						error: null
					});
				else
					return res.status(400).json({
						message: data,
						error: data
					});
			})
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error
				})
			);
	};

	this.unfollowSharkWallet = async (req, res, next) => {
		let { userId, sharkId } = req.body;

		if (!userId) userId = null;
		else {
			if (isNaN(userId)) userId = undefined;
			else userId = Number(userId);
		}

		if (!sharkId) sharkId = null;
		else {
			if (isNaN(sharkId)) sharkId = undefined;
			else sharkId = Number(sharkId);
		}

		await unfollowWalletOfShark(userId, sharkId)
			.then((data) => {
				if (data === "success")
					return res.status(200).json({
						message: "successfully",
						error: null
					});
				else
					return res.status(400).json({
						message: data,
						error: data
					});
			})
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error
				})
			);
	};

	this.getSharkFollowed = async (req, res, next) => {
		let userId = req.query.userId;

		if (!userId) userId = null;
		else {
			if (isNaN(userId)) userId = undefined;
			else userId = Number(userId);
		}

		await getListOfSharkFollowed(userId)
			.then((data) => {
				data.message === "success"
					? res.status(200).json({
							message: "successfully",
							error: null,
							datasLength: data.datas.length,
							datas: data.datas
					  })
					: res.status(400).json({
							message: data.message,
							error: data.message,
							datasLength: 0,
							datas: []
					  });
			})
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};
}

module.exports = new UserController();
