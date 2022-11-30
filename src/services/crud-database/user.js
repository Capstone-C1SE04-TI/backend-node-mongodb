const {
	UserModel,
	TokenModel,
	SharkModel,
	TagModel,
	TransactionModel
} = require("../../models");
const {
	QUERY_LIMIT_ITEM,
	TRENDING_REDUCING_LIMIT_ITEM
} = require("../../constants");

const getUserByUsername = async (username) => {
	return await UserModel.findOne({ username: username });
};

const getUserByEmail = async (email) => {
	return await UserModel.findOne({ email: email });
};

const getUsersLength = async () => {
	return await UserModel.count({});
};

const createNewUser = async ({
	username,
	email,
	phoneNumber,
	hashPassword
}) => {
	try {
		const newUserInfo = {
			username: username,
			email: email,
			phoneNumber: phoneNumber,
			password: hashPassword
		};

		await UserModel.create(newUserInfo)
			.then((data) => {})
			.catch((error) => {
				throw new Error(error);
			});

		return true;
	} catch (error) {
		return false;
	}
};

const updateUserConfirmationCode = async (userId, code) => {
	try {
		await UserModel.findOneAndUpdate(
			{ userId: userId },
			{ confirmationCode: code }
		)
			.then((data) => {
				if (!data) throw new Error();
			})
			.catch((error) => {
				throw new Error(error);
			});

		return true;
	} catch (error) {
		return false;
	}
};

const updateUserPassword = async (userId, password) => {
	try {
		await UserModel.findOneAndUpdate(
			{ userId: userId },
			{ password: password }
		)
			.then((data) => {
				if (!data) throw new Error();
			})
			.catch((error) => {
				throw new Error(error);
			});

		return true;
	} catch (error) {
		return false;
	}
};

const checkExistedUsername = async (username) => {
	const isExisted = await UserModel.exists({ username: username });
	return Boolean(isExisted);
};

const checkExistedEmail = async (email) => {
	const isExisted = await UserModel.exists({ email: email });
	return Boolean(isExisted);
};

const checkExistedUserId = async (userId) => {
	const isExisted = await UserModel.exists({ userId: userId });
	return Boolean(isExisted);
};

const checkExistedSharkId = async (sharkId) => {
	const isExisted = await SharkModel.exists({ sharkId: sharkId });
	return Boolean(isExisted);
};

const getPasswordByUsername = async (username) => {
	const user = await UserModel.findOne({ username: username }).select(
		"password -_id"
	);
	return user?.password || null;
};

const getPasswordByEmail = async (email) => {
	const user = await UserModel.findOne({ email: email }).select(
		"password -_id"
	);
	return user?.password || null;
};

const getListOfCoinsAndTokens = async () => {
	const tokens = await TokenModel.find({})
		.select(
			"id name symbol iconURL tagNames cmcRank usd marketCap circulatingSupply pricesLast1Day -_id"
		)
		.sort("id");

	return tokens || [];
};

const getCoinsAndTokensLength = async () => {
	return await TokenModel.count({});
};

const getListReducingCoinsAndTokens = async () => {
	return await TokenModel.find({})
		.sort({ "usd.percentChange24h": "asc" })
		.limit(TRENDING_REDUCING_LIMIT_ITEM)
		.select("id name symbol iconURL tagNames usd pricesLast1Day -_id");
};

const getListTrendingCoins = async () => {
	return await TokenModel.find({ type: "coin" })
		.sort({ "usd.percentChange24h": "desc" })
		.limit(TRENDING_REDUCING_LIMIT_ITEM)
		.select(
			"id name symbol iconURL tagNames usd marketCap circulatingSupply -_id"
		);
};

const getListTrendingTokens = async () => {
	return await TokenModel.find({ type: "token" })
		.sort({ "usd.percentChange24h": "desc" })
		.limit(TRENDING_REDUCING_LIMIT_ITEM)
		.select(
			"id name symbol iconURL tagNames usd marketCap circulatingSupply -_id"
		);
};

const getCoinOrTokenDetails = async (coinSymbol) => {
	coinSymbol = coinSymbol.toLowerCase()
	const coinOrToken = await TokenModel.findOne({
		symbol: coinSymbol
	}).select(
		"id ethId name type symbol iconURL cmcRank tagNames maxSupply totalSupply circulatingSupply contractAddress marketCap urls usd prices -_id"
	);

	return coinOrToken || {};
};

const getListOfTags = async () => {
	return await TagModel.find({}).sort("id").select("id name -_id");
};

const getSharksLength = async () => {
	return await SharkModel.count({});
};

const getListOfSharks = async (userId) => {
	const sharks = await SharkModel.find({})
		.sort("sharkId")
		.select("sharkId walletAddress totalAssets percent24h followers -_id");

	sharksList = sharks.map((shark) => {
		const isFollowed = shark.followers.includes(userId);
		let objShark = { ...shark._doc, isFollowed: isFollowed };
		return objShark;
	});

	return sharksList;
};

const followWalletOfShark = async (userId, sharkId) => {
	try {
		if (userId === null) return "userid-required";
		if (userId === undefined) return "userid-invalid";

		if (sharkId === null) return { message: "sharkid-required" };
		if (sharkId === undefined) return { message: "sharkid-invalid" };

		if (!(await checkExistedUserId(userId)))
			return { message: "user-notfound" };
		if (!(await checkExistedSharkId(sharkId)))
			return { message: "shark-notfound" };

		const shark = await SharkModel.findOne({ sharkId: sharkId }).select(
			"sharkId walletAddress totalAssets percent24h followers -_id"
		);

		const sharkFollowers = shark.followers;

		if (sharkFollowers && sharkFollowers.some((id) => id === userId))
			return { message: "already-followed" };

		sharkFollowers.push(userId);

		await SharkModel.findOneAndUpdate(
			{ sharkId: sharkId },
			{ followers: sharkFollowers },
			{ new: true }
		)
			.then((data) => {
				if (!data) throw new Error();
			})
			.catch((error) => {
				throw new Error(error);
			});

		shark.followers = sharkFollowers;

		const followInfo = { ...shark._doc, isFollowed: true };

		return { message: "success", data: followInfo };
	} catch (error) {
		return { message: "error-follow-failed", error: error };
	}
};

const unfollowWalletOfShark = async (userId, sharkId) => {
	try {
		if (userId === null) return "userid-required";
		if (userId === undefined) return "userid-invalid";
		if (sharkId === null) return { message: "sharkid-required" };
		if (sharkId === undefined) return { message: "sharkid-invalid" };
		if (!(await checkExistedUserId(userId)))
			return { message: "user-notfound" };
		if (!(await checkExistedSharkId(sharkId)))
			return { message: "shark-notfound" };
		const shark = await SharkModel.findOne({ sharkId: sharkId }).select(
			"sharkId walletAddress totalAssets percent24h followers -_id"
		);
		let sharkFollowers = shark.followers;
		if (sharkFollowers && !sharkFollowers.some((id) => id === userId))
			return { message: "not-followed-yet" };
		// Remove object has key id === sharkId
		sharkFollowers = sharkFollowers.filter((id) => id !== userId);
		await SharkModel.findOneAndUpdate(
			{ sharkId: sharkId },
			{ followers: sharkFollowers }
		)
			.then((data) => {
				if (!data) throw new Error();
			})
			.catch((error) => {
				throw new Error(error);
			});
		shark.followers = sharkFollowers;
		const infoUnfollow = { ...shark._doc, isFollowed: false };
		return { message: "success", data: infoUnfollow };
	} catch (error) {
		return { message: "error-unfollow-failed", error: error };
	}
};

const getListOfSharkFollowed = async (userId) => {
	if (userId === null) return { message: "userid-required" };
	if (userId === undefined) return { message: "userid-invalid" };
	if (!(await checkExistedUserId(userId)))
		return { message: "user-notfound" };

	const users = await SharkModel.find({ followers: userId }).select(
		"id totalAssets percent24h transactionsHistory -_id"
	);

	return { message: "success", datas: users || [] };
};

const getListCryptosOfShark1 = async (sharkId) => {
	const shark = await SharkModel.findOne({ sharkId: sharkId }).select(
		"cryptos -_id"
	);
	return shark?.cryptos || -1;
};

const getListCryptosOfShark = async (sharkId) => {
	// if (!_.isNumber(sharkId)) return -1;
	const rawData = await SharkModel.findOne({ sharkId: sharkId }).select(
		"coins -_id"
	);

	const coins = rawData.coins;

	let cryptos = Object.keys(coins).map(async (coinSymbol) => {
		const coinDetails = await getCoinOrTokenDetails(coinSymbol.toLowerCase());
		let quantity = coins[coinSymbol];
		if (typeof quantity === "object")
			quantity = Number(quantity["$numberLong"]);

		if (Object.keys(coinDetails).length === 0)
			return {
				symbol: coinSymbol,
				quantity: quantity
			};
		else {
			return {
				symbol: coinSymbol,
				quantity: quantity,
				name: coinDetails["name"],
				tagNames: coinDetails["tagNames"],
				cmcRank: coinDetails["cmcRank"],
				iconURL: coinDetails["iconURL"],
				price: coinDetails["usd"]["price"],
				total: Math.floor(coinDetails["usd"]["price"] * quantity)
			};
		}
	});


	cryptos = await getValueFromPromise(cryptos); 

	await SharkModel.findOneAndUpdate({sharkId: sharkId},
		{cryptos: cryptos});

	return cryptos || -1;

};

const getValueFromPromise = async (promiseValue) => {
    const value = await Promise.all(promiseValue);
    return value;
};

const getTransactionsLength = async (valueFilter = 0) => {
	return await TransactionModel.aggregate([
		{
			$project: {
				total: { $multiply: ["$presentPrice", "$numberOfTokens"] }
			}
		},

		{ $match: { total: { $gte: valueFilter } } },
		{ $count: "transactionsLength" }
	]);
};

const getTransactionsOfAllSharks = async (page, valueFilter = 0) => {
	if (page < 1 || page % 1 !== 0) return [];

	const transactions = await TransactionModel.aggregate([
		{
			$project: {
				_id: 0,
				timeStamp: 1,
				sharkId: 1,
				hash: 1,
				from: 1,
				to: 1,
				numberOfTokens: 1,
				pastPrice: 1,
				presentPrice: 1,
				total: { $multiply: ["$presentPrice", "$numberOfTokens"] }
			}
		},

		{ $match: { total: { $gte: valueFilter } } }
	])
		// .where("total")
		// .gte(valueFilter)
		.sort({ timeStamp: "desc" })
		.skip((page - 1) * QUERY_LIMIT_ITEM)
		.limit(QUERY_LIMIT_ITEM);

	// .select("-_id")

	return transactions || [];
};

const getListTransactionsOfShark = async (sharkId) => {
	const shark = await SharkModel.findOne({ sharkId: sharkId }).select(
		"transactionsHistory -_id"
	);
	return shark?.transactionsHistory || -1;
};

const getTradeTransactionHistoryOfShark = async (sharkId, coinSymbol) => {
	try {
		if (sharkId === null) return { message: "sharkid-required" };
		if (sharkId === undefined) return { message: "sharkid-invalid" };
		if (!coinSymbol) return { message: "coinsymbol-required" };
		if (!(await checkExistedSharkId(sharkId)))
			return { message: "shark-notfound" };

		const sharks = await SharkModel.findOne({ sharkId: sharkId }).select(
			"historyDatas cryptos -_id"
		);
		const { historyDatas, cryptos } = sharks;

		const historyData = historyDatas.find(
			(data) => data.coinSymbol === coinSymbol.toUpperCase()
		);

		const coinInfo = await TokenModel.findOne({
			symbol: coinSymbol.toUpperCase()
		}).select(
			"ethId name symbol iconURL cmcRank maxSupply totalSupply circulatingSupply marketCap contractAddress prices -_id"
		);

		if (!historyData) {
			if (
				cryptos &&
				cryptos.find(
					(crypto) => crypto.symbol === coinSymbol.toUpperCase()
				)
			) {
				return {
					message: "success",
					data: {
						historyData: null,
						coinInfo: coinInfo || null
					}
				};
			} else {
				return { message: "coin-notfound" };
			}
		} else {
			return {
				message: "success",
				data: {
					historyData: historyData.historyData || null,
					coinInfo: coinInfo || null
				}
			};
		}
	} catch (error) {
		return { message: "error" };
	}
};

const getHoursPriceOfToken = async (tokenSymbol) => {
	const token = await TokenModel.findOne({
		symbol: tokenSymbol.toUpperCase()
	}).select("originalPrices -_id");

	return token?.originalPrices?.hourly || {};
};

const getGainLossOfSharks = async (isLoss) => {
	const sortType = isLoss ? "asc" : "desc";
	const sharkGainLoss = isLoss
		? await SharkModel.find({})
				.select("sharkId totalAssets percent24h -_id")
				.where("percent24h")
				.lt(0)
				.sort({ percent24h: sortType })
				.limit(20)
		: await SharkModel.find({})
				.select("sharkId totalAssets percent24h -_id")
				.where("percent24h")
				.gte(0)
				.sort({ percent24h: sortType })
				.limit(20);

	return sharkGainLoss;
};

const getGainLossOfCoins = async (isLoss) => {
	const sortType = isLoss ? "asc" : "desc";
	const sharkGainLoss = isLoss
		? await TokenModel.find({})
				.select("symbol usd.price usd.percentChange24h -_id")
				.where("usd.percentChange24h")
				.lt(0)
				.sort({ "usd.percentChange24h": sortType })
				.limit(20)
		: await TokenModel.find({})
				.select("symbol usd.price usd.percentChange24h -_id")
				.where("usd.percentChange24h")
				.gte(0)
				.sort({ "usd.percentChange24h": sortType })
				.limit(20);

	return sharkGainLoss;
};

const addNewShark = async (walletAddress) => {
	try {
		const addedData = await SharkModel.create({
			walletAddress: walletAddress
		});

		return addedData instanceof SharkModel
			? { message: "successful", isAdded: true }
			: { message: "wallet-address-exists", isAdded: false };
	} catch (error) {
		return { message: "error", error: error };
	}
};

const deleteSharkNotFound = async (walletAddress) => {
	try {
		const deletedData = await SharkModel.remove({
			walletAddress: walletAddress
		});
		return deletedData.deletedCount > 0
			? { message: "successful", isDeleted: true }
			: { message: "wallet-address-notfound", isDeleted: false };
	} catch (error) {
		return { message: "error", error: error };
	}
};

module.exports = {
	getUserByUsername,
	getUserByEmail,
	getUsersLength,
	createNewUser,
	updateUserConfirmationCode,
	updateUserPassword,
	checkExistedUsername,
	checkExistedEmail,
	checkExistedUserId,
	checkExistedSharkId,
	getPasswordByUsername,
	getPasswordByEmail,
	getListOfCoinsAndTokens,
	getCoinsAndTokensLength,
	getCoinOrTokenDetails,
	getListOfSharks,
	getSharksLength,
	getListOfTags,
	getListReducingCoinsAndTokens,
	getListTrendingCoins,
	getListTrendingTokens,
	getListCryptosOfShark,
	getTransactionsLength,
	getTransactionsOfAllSharks,
	getListTransactionsOfShark,
	getTradeTransactionHistoryOfShark,
	getHoursPriceOfToken,
	getTransactionsLength,
	getGainLossOfSharks,
	getGainLossOfCoins,
	getListOfSharkFollowed,
	followWalletOfShark,
	unfollowWalletOfShark,
	addNewShark,
	deleteSharkNotFound
};
