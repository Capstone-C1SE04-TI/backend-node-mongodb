const { AdminModel, UserModel } = require("../../models");
const { checkExistedUserId } = require("./user");

const getListOfAdmins = async () => {
	const admins = await AdminModel.find({})
		.sort("id")
		.select("id username email  -_id");

	return admins;
};

const getListOfUsers = async () => {
	const users = await UserModel.find({})
		.sort("id")
		.select(
			"userId username email phoneNumber fullName avatar website sharksFollowed updatedAt createdAt  -_id"
		);

	return users;
};

const getUserProfile = async (userId) => {
	if (!userId) return {};
	else {
		const user = await UserModel.findOne({ userId: userId }).select(
			"userId username email phoneNumber fullName avatar website sharksFollowed updatedAt createdAt  -_id"
		);

		if (!user) return {};
		else return user;
	}
};

const checkExistedUsernameForUpdateProfile = async (userId, username) => {
	const user = await UserModel.findOne({ username: username });

	if (user && user.userId !== userId) return true;
	else return false;
};

const checkExistedEmailForUpdateProfile = async (userId, email) => {
	const user = await UserModel.findOne({ email: email });

	if (user && user.userId !== userId) return true;
	else return false;
};

const updateUserProfile = async (userId, updateInfo) => {
	try {
		if (!userId) return "userid-required";
		else {
			const { email } = updateInfo;

			if (!(await checkExistedUserId(userId))) return "user-notfound";

			if (
				email &&
				(await checkExistedEmailForUpdateProfile(userId, email))
			)
				return "email-existed";

			await UserModel.findOneAndUpdate({ userId: userId }, updateInfo)
				.then((data) => {
					if (!data) throw new Error();
				})
				.catch((error) => {
					throw new Error(error);
				});

			return "success";
		}
	} catch (error) {
		return "error";
	}
};

const upgradeUserPremiumAccount = async (userId) => {
	try {
		if (userId === null) return "userid-required";
		if (userId === undefined) return "userid-invalid";
		if (!(await checkExistedUserId(userId))) return "user-notfound";

		await UserModel.findOneAndUpdate(
			{ userId: userId },
			{ premiumAccount: true }
		)
			.then((data) => {
				if (!data) throw new Error();
			})
			.catch((error) => {
				throw new Error(error);
			});

		return "success";
	} catch (error) {
		return "error";
	}
};

const checkExistedUsername = async (username) => {
	const isExisted = await AdminModel.exists({ username: username });
	return Boolean(isExisted);
};

const getPasswordByUsername = async (username) => {
	const admin = await AdminModel.findOne({ username: username }).select(
		"password  -_id"
	);
	return admin?.password || null;
};

const getAdminByUsername = async (username) => {
	return await AdminModel.findOne({ username: username });
};

const deleteUsersByUserId = async (userIds) => {
	try {
		const deletedObj = await UserModel.remove({
			userId: { $in: userIds }
		});
		return deletedObj.deletedCount > 0;
	} catch (error) {
		return false;
	}
};

module.exports = {
	getListOfAdmins,
	getListOfUsers,
	getUserProfile,
	checkExistedUsername,
	checkExistedUsernameForUpdateProfile,
	checkExistedEmailForUpdateProfile,
	updateUserProfile,
	upgradeUserPremiumAccount,
	getPasswordByUsername,
	getAdminByUsername,
	deleteUsersByUserId
};
