const {
	validateUsername,
	validatePassword,
	returnValidationResult
} = require("./index.js");

const validateSignInBody = async (req, res, next) => {
	await validateUsername(req);
	await validatePassword(req);
	return returnValidationResult(req);
};

module.exports = {
	validateSignInBody
};
