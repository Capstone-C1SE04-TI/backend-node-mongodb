const dotenv = require("dotenv");
dotenv.config();

const jwt = require("jsonwebtoken");
const {
	getUserByUsername,
	getUserAccessTokens,
	saveAccessTokensToDB
} = require("../crud-database/user");
const promisify = require("util").promisify;
const sign = promisify(jwt.sign).bind(jwt);
const verify = promisify(jwt.verify).bind(jwt);

const {
	USER_ACCESS_TOKEN_SECRET,
	USER_REFRESH_ACCESS_TOKEN_SECRET,
	ENCODE_ALGORITHM
} = process.env;

const generateAccessToken = async (payloadData) => {
	try {
		const accessToken = await sign(payloadData, USER_ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "1d"
		});

		return accessToken;
	} catch (error) {
		return null;
	}
};

const generateRefreshAccessToken = async (payloadData) => {
	try {
		const refreshAccessToken = await sign(
			payloadData,
			USER_REFRESH_ACCESS_TOKEN_SECRET,
			{
				algorithm: ENCODE_ALGORITHM,
				expiresIn: "1d"
			}
		);

		return refreshAccessToken;
	} catch (error) {
		return null;
	}
};

const decodeToken = async (token, secretKey) => {
	try {
		return await verify(token, secretKey, {
			ignoreExpiration: true
		});
	} catch (error) {
		return undefined;
	}
};

const handleRefreshAccessToken = async (req) => {
	try {
		const { username, refreshAccessToken } = req.body;
		if (!username || !refreshAccessToken) return null;

		const decodeRefreshAccessToken = await decodeToken(
			refreshAccessToken,
			USER_REFRESH_ACCESS_TOKEN_SECRET
		);
		if (!decodeRefreshAccessToken) return null;

		const { refreshAccessToken: refreshAccessTokenInDB } =
			await getUserAccessTokens(username);
		if (
			refreshAccessToken !== refreshAccessTokenInDB ||
			decodeRefreshAccessToken.username !== username
		)
			return null;

		const newAccessToken = await generateAccessToken({
			username: username
		});
		const newRefreshAccessToken = await generateRefreshAccessToken({
			username: username
		});

		await saveAccessTokensToDB(
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

const isExpiredAccessToken = async (accessTokenHeader) => {
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

const isAuthed = async (req, res, next) => {
	const accessTokenHeader = req.headers.authorization;
	if (!accessTokenHeader) return { message: "failed-unauthorized" };

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		USER_ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return { message: "failed-unauthorized" };

	const tokensInDB = await getUserAccessTokens(decodeAccessToken.username);
	if (accessTokenHeader !== tokensInDB.accessToken)
		return { message: "failed-unauthorized" };

	if (await isExpiredAccessToken(accessTokenHeader))
		return { message: "failed-expired-token" };

	return { message: "successfully" };
};

module.exports = {
	generateAccessToken,
	generateRefreshAccessToken,
	handleRefreshAccessToken,
	decodeToken,
	isAuthed
};
