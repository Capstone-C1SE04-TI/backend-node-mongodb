const {
	sign,
	decodeToken,
	USER_ACCESS_TOKEN_SECRET,
	USER_REFRESH_ACCESS_TOKEN_SECRET,
	ENCODE_ALGORITHM
} = require("./index.js");
const {
	getUserAuthorizationByUsername,
	updateUserAuthorizationByUsername
} = require("../crud-database/user");

const generateUserAccessToken = async (payloadData) => {
	try {
		return await sign(payloadData, USER_ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "7d"
		});
	} catch (error) {
		return null;
	}
};

const generateUserRefreshAccessToken = async (payloadData) => {
	try {
		return await sign(payloadData, USER_REFRESH_ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "7d"
		});
	} catch (error) {
		return null;
	}
};

const isExpiredUserAccessToken = async (req) => {
	const accessTokenHeader = req.headers.authorization;

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		USER_ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return false;

	const tokenExpiredTimestamp = decodeAccessToken.exp;
	const currentTimestamp = Math.floor(new Date().getTime() / 1000);

	if (tokenExpiredTimestamp <= currentTimestamp) return true;
	else return false;
};

const handleRefreshUserAccessToken = async (req) => {
	try {
		const { username, refreshAccessToken } = req.body;
		if (!username || !refreshAccessToken) return null;

		const decodeRefreshAccessToken = await decodeToken(
			refreshAccessToken,
			USER_REFRESH_ACCESS_TOKEN_SECRET
		);
		if (!decodeRefreshAccessToken) return null;

		const { refreshAccessToken: refreshAccessTokenInDB } =
			await getUserAuthorizationByUsername(username);
		if (
			refreshAccessToken !== refreshAccessTokenInDB ||
			decodeRefreshAccessToken.username !== username
		)
			return null;

		const newAccessToken = await generateUserAccessToken({
			username: username
		});
		const newRefreshAccessToken = await generateUserRefreshAccessToken({
			username: username
		});

		await updateUserAuthorizationByUsername(
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

const isAuthedUser = async (req, res, next) => {
	const accessTokenHeader = req.headers.authorization;
	if (!accessTokenHeader) return false;

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		USER_ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return false;

	const authorizationInDB = await getUserAuthorizationByUsername(
		decodeAccessToken.username
	);
	if (accessTokenHeader !== authorizationInDB.accessToken) return false;

	return true;
};

module.exports = {
	generateUserAccessToken,
	generateUserRefreshAccessToken,
	isExpiredUserAccessToken,
	handleRefreshUserAccessToken,
	decodeToken,
	isAuthedUser
};
