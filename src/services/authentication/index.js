const dotenv = require("dotenv");
dotenv.config();

const jwt = require("jsonwebtoken");
const promisify = require("util").promisify;
const sign = promisify(jwt.sign).bind(jwt);
const verify = promisify(jwt.verify).bind(jwt);

const {
	getUserAuthorizationByUsername,
	updateUserAuthorizationByUsername
} = require("../crud-database/user");
const { ACCESS_TOKEN_SECRET, REFRESH_ACCESS_TOKEN_SECRET, ENCODE_ALGORITHM } =
	process.env;

const decodeToken = async (token, secretKey) => {
	try {
		return await verify(token, secretKey, {
			ignoreExpiration: true
		});
	} catch (error) {
		return undefined;
	}
};

const generateAccessToken = async (payloadData) => {
	try {
		return await sign(payloadData, ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "7d"
		});
	} catch (error) {
		return null;
	}
};

const generateRefreshAccessToken = async (payloadData) => {
	try {
		return await sign(payloadData, REFRESH_ACCESS_TOKEN_SECRET, {
			algorithm: ENCODE_ALGORITHM,
			expiresIn: "7d"
		});
	} catch (error) {
		return null;
	}
};

const isExpiredAccessToken = async (req) => {
	const accessTokenHeader = req.headers.authorization;

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return false;

	const tokenExpiredTimestamp = decodeAccessToken.exp;
	const currentTimestamp = Math.floor(new Date().getTime() / 1000);

	if (tokenExpiredTimestamp <= currentTimestamp) return true;
	else return false;
};

const handleRefreshAccessToken = async (req) => {
	try {
		const { username, refreshAccessToken } = req.body;
		if (!username || !refreshAccessToken) return null;

		const decodeRefreshAccessToken = await decodeToken(
			refreshAccessToken,
			REFRESH_ACCESS_TOKEN_SECRET
		);
		if (!decodeRefreshAccessToken) return null;

		const { refreshAccessToken: refreshAccessTokenInDB } =
			await getUserAuthorizationByUsername(username);
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

const isAuthed = async (req, res, next) => {
	const accessTokenHeader = req.headers.authorization;
	if (!accessTokenHeader) return false;

	const decodeAccessToken = await decodeToken(
		accessTokenHeader,
		ACCESS_TOKEN_SECRET
	);
	if (!decodeAccessToken) return false;

	const authorizationInDB = await getUserAuthorizationByUsername(
		decodeAccessToken.username
	);
	if (accessTokenHeader !== authorizationInDB.accessToken) return false;

	return true;
};

module.exports = {
	generateAccessToken,
	generateRefreshAccessToken,
	isExpiredAccessToken,
	handleRefreshAccessToken,
	decodeToken,
	isAuthed
};
