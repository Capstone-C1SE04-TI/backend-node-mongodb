const _ = require("lodash");
const {
	checkExistedUsername,
	getPasswordByUsername,
	getAdminByUsername,
	getListOfAdmins,
	deleteUsersByUserId,
	getListOfUsers,
	getUserProfile
} = require("../services/crud-database/admin");
const { comparePassword } = require("../helpers");
const { validateSignInBody } = require("../validators/admin");

function AdminController() {
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
						const admin = await getAdminByUsername(username);

						return res.status(200).json({
							message: "successfully",
							error: null,
							user: {
								role: "admin",
								username: admin.username,
								email: admin.email
							}
						});
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

	this.signout = async (req, res, next) => {
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

	this.getAdminsList = async (req, res, next) => {
		await getListOfAdmins()
			.then((datas) => {
				datas.length === 0
					? res.status(400).json({
							message: "failed-empty-data",
							error: "empty-data",
							datasLength: 0,
							datas: []
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datasLength: datas.length,
							datas: datas
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

	this.deleteUsers = async (req, res, next) => {
		try {
			const { ids } = req.body;

			const checkedIds = ids;
			checkedIds.forEach((id) => {
				id = Number(id);
				if (_.isNaN(id)) {
					Error.captureStackTrace(err);
				}
			});

			const isDeletedSuccessful = await deleteUsersByUserId(checkedIds);

			if (!isDeletedSuccessful)
				return res.status(404).json({
					message: "ids-notfound",
					error: "ids-notfound"
				});

			return res
				.status(200)
				.json({ message: "successfully", error: null });
		} catch (error) {
			return res.status(400).json({ message: "failed", error: error });
		}
	};

	this.getUsersList = async (req, res, next) => {
		await getListOfUsers()
			.then((datas) => {
				datas.length === 0
					? res.status(400).json({
							message: "failed-empty-data",
							error: "empty-data",
							datasLength: 0,
							datas: []
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datasLength: datas.length,
							datas: datas
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

	this.getUserDetail = async (req, res, next) => {
		let userId;

		if (!req.query.userId) userId = null;
		else {
			const userIdCheck = _.toString(req.query.userId);
			if (_.isNaN(userIdCheck)) userId = undefined;
			else userId = Number(userIdCheck);
		}

		await getUserProfile(userId)
			.then((data) => {
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
					  });
			})
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					data: {}
				})
			);
	};
}

module.exports = new AdminController();
