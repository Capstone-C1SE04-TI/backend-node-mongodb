const {
	sign,
	decodeToken,
	ADMIN_ACCESS_TOKEN_SECRET,
	ADMIN_REFRESH_ACCESS_TOKEN_SECRET,
	ENCODE_ALGORITHM
} = require("./index.js");
const {
	getAdminAuthorizationByUsername,
	updateAdminAuthorizationByUsername
} = require("../crud-database/admin");

const generateAdminAccessToken = async (payloadData) => {
	try {
		return await sign(payloadData, ADMIN_ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "7d"
		});
	} catch (error) {
		return null;
	}
};

const generateRefreshAdminAccessToken = async (payloadData) => {
	try {
		return await sign(payloadData, ADMIN_REFRESH_ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "7d"
		});
	} catch (error) {
		return null;
	}
};

const isExpiredAdminAccessToken = async (req) => {
	const accessTokenHeader = req.headers.authorization;

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		ADMIN_ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return false;

	const tokenExpiredTimestamp = decodeAccessToken.exp;
	const currentTimestamp = Math.floor(new Date().getTime() / 1000);

	if (tokenExpiredTimestamp <= currentTimestamp) return true;
	else return false;
};

const handleRefreshAdminAccessToken = async (req) => {
	try {
		const { username, refreshAccessToken } = req.body;
		if (!username || !refreshAccessToken) return null;

		const decodeRefreshAccessToken = await decodeToken(
			refreshAccessToken,
			ADMIN_REFRESH_ACCESS_TOKEN_SECRET
		);
		if (!decodeRefreshAccessToken) return null;

		const { refreshAccessToken: refreshAccessTokenInDB } =
			await getAdminAuthorizationByUsername(username);
		if (
			refreshAccessToken !== refreshAccessTokenInDB ||
			decodeRefreshAccessToken.username !== username ||
			decodeRefreshAccessToken.role !== "admin"
		)
			return null;

		const newAccessToken = await generateAdminAccessToken({
			username: username,
			role: "admin"
		});
		const newRefreshAccessToken = await generateRefreshAdminAccessToken({
			username: username,
			role: "admin"
		});

		await updateAdminAuthorizationByUsername(
			username,
			newAccessToken,
			newRefreshAccessToken
		);

		return {
			accessToken: newAccessToken,
			refreshAccessToken: newRefreshAccessToken
		};
	} catch (error) {
		return null;
	}
};

const isAuthedAdmin = async (req, res, next) => {
	const accessTokenHeader = req.headers.authorization;
	if (!accessTokenHeader) return false;

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		ADMIN_ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return false;

	const authorizationInDB = await getAdminAuthorizationByUsername(
		decodeAccessToken.username
	);
	if (accessTokenHeader !== authorizationInDB.accessToken) return false;

	if (decodeAccessToken.role !== "admin") return false;

	return true;
};

module.exports = {
	generateAdminAccessToken,
	generateRefreshAdminAccessToken,
	isExpiredAdminAccessToken,
	handleRefreshAdminAccessToken,
	isAuthedAdmin
};
