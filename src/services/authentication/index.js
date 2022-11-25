const dotenv = require("dotenv");
dotenv.config();

const jwt = require("jsonwebtoken");
const promisify = require("util").promisify;
const sign = promisify(jwt.sign).bind(jwt);
const verify = promisify(jwt.verify).bind(jwt);

const {
	ENCODE_ALGORITHM,
	USER_ACCESS_TOKEN_SECRET,
	USER_REFRESH_ACCESS_TOKEN_SECRET,
	ADMIN_ACCESS_TOKEN_SECRET,
	ADMIN_REFRESH_ACCESS_TOKEN_SECRET
} = process.env;

const decodeToken = async (token, secretKey) => {
	try {
		return await verify(token, secretKey, {
			ignoreExpiration: true
		});
	} catch (error) {
		return undefined;
	}
};

module.exports = {
	sign,
	verify,
	decodeToken,
	ENCODE_ALGORITHM,
	USER_ACCESS_TOKEN_SECRET,
	USER_REFRESH_ACCESS_TOKEN_SECRET,
	ADMIN_ACCESS_TOKEN_SECRET,
	ADMIN_REFRESH_ACCESS_TOKEN_SECRET
};
