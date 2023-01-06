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

// const refreshAccessToken = async (refreshToken, userId) => {
// 	try {
// 		const refreshAccessToken = await decodeToken(
// 			refreshToken,
// 			USER_REFRESH_ACCESS_TOKEN_SECRET
// 		);

// 		const user = await UserModel.find({ userId: userId }).select(
// 			"accessToken refreshAccessToken username -_id"
// 		);

// 		// Check valid refreshToken
// 		if (user.refreshAccessToken !== refreshAccessToken) return null;

// 		// Generate new tokens
// 		const payloadData = {
// 			username: user.username
// 		};
// 		const newAccessToken = await generateAccessToken(payloadData);
// 		const newRefreshAccessToken = await generateRefreshAccessToken(
// 			payloadData
// 		);

// 		return { newAccessToken, newRefreshAccessToken };
// 	} catch (error) {
// 		return null;
// 	}
// };

const decodeToken = async (token, secretKey) => {
	try {
		return await verify(token, secretKey, {
			ignoreExpiration: true
		});
	} catch (error) {
		return undefined;
	}
};

const isExpiredAccessToken = async (req) => {
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

const refreshAccessToken = async (req) => {
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

const isAuthed = async (req, res, next) => {
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
	generateAccessToken,
	generateRefreshAccessToken,
	refreshAccessToken,
	decodeToken,
	isAuthed
};
