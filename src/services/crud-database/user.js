const {
	UserModel,
	CoinModel,
	InvestorModel,
	TagModel,
	TransactionModel
} = require("../../models");
const {
	QUERY_LIMIT_ITEM,
	TRENDING_REDUCING_LIMIT_ITEM
} = require("../../constants");
const { convertUnixTimestampToNumber } = require("../../helpers");
const { log } = require("util");

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
	const isExisted = await InvestorModel.exists({ sharkId: sharkId });
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
	const tokens = await CoinModel.find({})
		.select(
			"coinId name type symbol iconURL tagNames cmcRank usd marketCap circulatingSupply pricesLast1Month -_id"
		)
		.sort("coinId");

	return tokens || [];
};

const getCoinsAndTokensLength = async () => {
	return await CoinModel.count({});
};

const getListReducingCoinsAndTokens = async () => {
	return await CoinModel.find({})
		.sort({ "usd.percentChange24h": "asc" })
		.limit(TRENDING_REDUCING_LIMIT_ITEM)
		.select(
			"coinId name type symbol iconURL tagNames usd pricesLast1Month -_id"
		);
};

const getListTrendingCoins = async () => {
	return await CoinModel.find({ type: "coin" })
		.sort({ "usd.percentChange24h": "desc" })
		.limit(TRENDING_REDUCING_LIMIT_ITEM)
		.select(
			"coinId name type symbol iconURL tagNames usd marketCap circulatingSupply -_id"
		);
};

const getListTrendingTokens = async () => {
	return await CoinModel.find({ type: "token" })
		.sort({ "usd.percentChange24h": "desc" })
		.limit(TRENDING_REDUCING_LIMIT_ITEM)
		.select(
			"coinId name type symbol iconURL tagNames usd marketCap circulatingSupply -_id"
		);
};

const getCoinOrTokenDetails = async (coinSymbol) => {
	const coinOrToken = await CoinModel.findOne({
		symbol: coinSymbol.toLowerCase()
	}).select(
		"coinId ethId coingeckoId name type symbol iconURL cmcRank tagNames maxSupply totalSupply circulatingSupply contractAddress marketCap urls usd prices totalInvestment -_id"
	);

	return coinOrToken || {};
};

const getListOfTags = async () => {
	return await TagModel.find({}).sort("id").select("id name -_id");
};

const getSharksLength = async () => {
	return await InvestorModel.count({});
};

const getListOfSharks = async (userId) => {
	const sharks = await InvestorModel.find({ isShark: true })
		.sort("sharkId")
		.select(
			"sharkId walletAddress totalAssets percent24h followers isShark -_id"
		);

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

		const shark = await InvestorModel.findOne({ sharkId: sharkId }).select(
			"sharkId walletAddress totalAssets percent24h followers -_id"
		);

		const sharkFollowers = shark.followers;

		if (sharkFollowers && sharkFollowers.some((id) => id === userId))
			return { message: "already-followed" };

		sharkFollowers.push(userId);

		await InvestorModel.findOneAndUpdate(
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

		const shark = await InvestorModel.findOne({ sharkId: sharkId }).select(
			"sharkId walletAddress totalAssets percent24h followers -_id"
		);
		let sharkFollowers = shark.followers;

		if (sharkFollowers && !sharkFollowers.some((id) => id === userId))
			return { message: "not-followed-yet" };

		// Remove object has key id === sharkId
		sharkFollowers = sharkFollowers.filter((id) => id !== userId);
		await InvestorModel.findOneAndUpdate(
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

	const projection = {
		sharkId: 1,
		totalAssets: 1,
		percent24h: 1,
		walletAddress: 1
	};

	const users = await InvestorModel.find(
		{ followers: { $in: [userId] } },
		projection
	);

	return { message: "success", datas: users || [] };
};

const getListCryptosOfShark = async (sharkId) => {
	const shark = await InvestorModel.findOne({ sharkId: sharkId }).select(
		"cryptos -_id"
	);
	return shark?.cryptos || -1;
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
	let transactions = await InvestorModel.find({
		"transactionsHistory.500": { $exists: 0 },
		isShark: 1
	}).select("sharkId walletAddress transactionsHistory -_id");
	transactions = transactions.reduce((curr, transaction) => {
		transaction.transactionsHistory = transaction.transactionsHistory.map(
			(trans) => {
				return Object.assign(
					{
						sharkId: transaction.sharkId,
						walletAddress: transaction.walletAddress
					},
					trans
				);
			}
		);
		return curr.concat(transaction.transactionsHistory);
	}, []);

	transactions.forEach(async (transac) => {
		const doc = new TransactionModel(transac);
		await doc.save();
	});

	return transactions;
};

const getTransactionsOfAllSharks1 = async (page, valueFilter = 0) => {
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

	return transactions || [];
};

const getValueFromPromise = async (promiseValue) => {
	const value = await Promise.all(promiseValue);
	return value;
};

const getDateNearTransaction = (dateList, dateTransaction) => {
	let datePricesTokenCut = dateList.map((date) => {
		return date["date"].slice(0, 10);
	});

	let dateTransactionCut = dateTransaction.slice(0, 10);
	let positionDate = null;
	// Cut hour
	let dateCutByHours = datePricesTokenCut.filter((date, index) => {
		if (Number(date) === Number(dateTransactionCut)) positionDate = index;
		return Number(date) === Number(dateTransactionCut);
	});

	if (dateCutByHours.length > 0) {
		// date transaction before date change price
		if (Number(dateTransaction) < Number(dateList[positionDate]))
			return positionDate === dateList.length - 1
				? dateList[dateList.length - 1]
				: dateList[positionDate + 1];
		else return dateList[positionDate];
	}

	// cut date
	if (positionDate === null) {
		let dateCutByDates = datePricesTokenCut.filter((date, index) => {
			date = date.slice(0, 8);
			if (Number(date) === Number(dateTransactionCut.slice(0, 8)))
				positionDate = index;
			return Number(date) === Number(dateTransactionCut.slice(0, 8));
		});

		let hourTrade = dateTransactionCut.slice(8);
		let datesCutLength = dateCutByDates.length;
		for (let i = 0; i < datesCutLength; i++) {
			if (Number(hourTrade) > Number(dateCutByDates[i].slice(8)))
				return dateList[positionDate - datesCutLength + i + 1];
		}
	}

	return positionDate === null
		? {
				date: "notfound",
				value: 0
		  }
		: positionDate === dateList.length - 1
		? dateList[dateList.length - 1]
		: dateList[positionDate + 1];
};

// update
const getListTransactionsOfShark = async (sharkId) => {

	// if (!_.isNumber(sharkId)) return -1;
	const rawData = await InvestorModel.find(
		{ "transactionsHistory.500": { $exists: 0 }, isShark: 1 },
		{ transactionsHistory: 1, sharkId: 1 }
	);
	// .limit(50)
	// .skip(2)
	// "transactionsHistory.500": { $exists: 0 },
	// return rawData[0].transactionsHistory;
	console.log("done phase 1");

	// for(let sharkIndex = 0; sharkIndex <= rawData.length; ++sharkIndex){
	// 	console.log(sharkIndex);
	// }
	await rawData.forEach(async (element) => {
		console.log(element.sharkId);
		let transactions = await element.transactionsHistory.map(
			async (transaction) => {
				let numberOfTokens =
					Number(transaction["value"]) /
					10 ** Number(transaction["tokenDecimal"]);

				let originalPrices = await getOriginalPriceOfToken(
					transaction["tokenSymbol"]
				);

				let hoursPrice = originalPrices.hourly;

				// found hourly price
				if (typeof hoursPrice !== "undefined") {
					hoursPrice = Object.keys(hoursPrice).map((unixDate) => {
						let date = convertUnixTimestampToNumber(unixDate);
						date = date.toString();
						return {
							date: date,
							value: hoursPrice[unixDate]
						};
					});

					hoursPrice.sort(
						(firstObj, secondObj) =>
							secondObj["date"] - firstObj["date"]
					);
				}

				let presentData =
					typeof hoursPrice !== "undefined"
						? hoursPrice[0]
						: undefined;

				const dateTransac = convertUnixTimestampToNumber(
					transaction["timeStamp"]
				);
				let dateNearTransaction =
					typeof hoursPrice !== "undefined"
						? getDateNearTransaction(
								hoursPrice,
								dateTransac.toString()
						  )
						: { date: "none", value: 0 };

				if (dateNearTransaction.date === "notfound") {
					// console.log(hoursPrice[0]);
					// console.log(dateNearTransaction);
					let dailyPrice = originalPrices.daily;
					dateNearTransaction = getPriceWithDaily(
						dailyPrice,
						dateTransac.toString()
					);
					// console.log(dateNearTransaction);
				}

				if (
					transaction["hash"] ===
					"0x0e1fff155f5d43c813e75095ec50f8dd41d0205a56867e17c6f6dd0a7bb21fd6"
				)
					console.log(dateNearTransaction);

				let presentPrice =
					typeof presentData === "undefined"
						? 0
						: presentData["value"];

				let presentDate =
					typeof presentData === "undefined"
						? 0
						: presentData["date"];

				Object.assign(transaction, {
					numberOfTokens: numberOfTokens,
					pastDate: dateNearTransaction["date"],
					pastPrice: dateNearTransaction["value"],
					presentDate: presentDate,
					presentPrice: presentPrice
				});

				return transaction;
			}
		);
		transactions = await getValueFromPromise(transactions);

		await InvestorModel.updateOne(
			{ sharkId: element.sharkId },
			{ transactionsHistory: transactions }
		);
	});
	console.log("done phase 2");

	return 1;
};

const getPriceWithDaily = (dailyPrice, dateTransaction) => {
	if (typeof dailyPrice !== "undefined") {
		dailyPrice = Object.keys(dailyPrice).map((unixDate) => {
			let date = convertUnixTimestampToNumber(unixDate);
			date = date.toString();
			return {
				date: date,
				value: dailyPrice[unixDate]
			};
		});

		dailyPrice.sort(
			(firstObj, secondObj) => secondObj["date"] - firstObj["date"]
		);

		const dateNearTransaction = getDateNearTransaction(
			dailyPrice,
			dateTransaction
		);
		// console.log(dateNearTransaction);
		return dateNearTransaction;
	}

	return { date: "none", value: 0 };
};

const getListTransactionsOfShark1 = async (sharkId) => {
	const shark = await InvestorModel.findOne({ sharkId: sharkId }).select(
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

		const sharks = await InvestorModel.findOne({ sharkId: sharkId }).select(
			"historyDatas cryptos -_id"
		);
		const { historyDatas, cryptos } = sharks;

		// Need reset to toLowerCase()
		const historyData = historyDatas.find(
			(data) => data.coinSymbol === coinSymbol.toUpperCase()
		);

		const coinInfo = await CoinModel.findOne({
			symbol: coinSymbol.toLowerCase()
		}).select(
			"coinId name symbol iconURL cmcRank maxSupply totalSupply circulatingSupply marketCap contractAddress prices -_id"
		);

		// Need reset to toLowerCase()
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

const getOriginalPriceOfToken = async (tokenSymbol) => {
	const token = await CoinModel.findOne({
		symbol: tokenSymbol.toLowerCase()
	}).select("originalPrices -_id");

	return token?.originalPrices || {};
};

const getGainLossOfSharks = async (isLoss) => {
	const sortType = isLoss ? "asc" : "desc";
	const sharkGainLoss = isLoss
		? await InvestorModel.find({})
				.select("sharkId totalAssets percent24h -_id")
				.where("percent24h")
				.lt(0)
				.sort({ percent24h: sortType })
				.limit(20)
		: await InvestorModel.find({})
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
		? await CoinModel.find({})
				.select("symbol usd.price usd.percentChange24h -_id")
				.where("usd.percentChange24h")
				.lt(0)
				.sort({ "usd.percentChange24h": sortType })
				.limit(20)
		: await CoinModel.find({})
				.select("symbol usd.price usd.percentChange24h -_id")
				.where("usd.percentChange24h")
				.gte(0)
				.sort({ "usd.percentChange24h": sortType })
				.limit(20);

	return sharkGainLoss;
};

const addNewShark = async (walletAddress, userId) => {
	try {
		if (!(await checkExistedUserId(userId)))
			return { message: "user-notfound", isAdded: false };

		const sharkExisted = await InvestorModel.findOne({
			walletAddress: walletAddress
		});

		if (sharkExisted !== null)
			return { message: "wallet-address-exists", isAdded: false };

		const addedData = await InvestorModel.create({
			walletAddress: walletAddress,
			isShark: true
		});

		const user = await UserModel.findOneAndUpdate(
			{ userId: userId },
			{ $push: { addedSharks: walletAddress } },
			{ new: true }
		);

		let addedSharks = user.addedSharks;

		return {
			message: "successfully",
			isAdded: true,
			data: addedData,
			sharkAdded: addedSharks
		};
	} catch (error) {
		return { message: "error", error: error };
	}
};

const deleteSharkNotFound = async (walletAddress, userId) => {
	try {
		if (!(await checkExistedUserId(userId)))
			return { message: "user-notfound", isDeleted: false };

		const sharkExisted = await InvestorModel.findOne({
			walletAddress: walletAddress
		});

		if (sharkExisted === null)
			return { message: "wallet-address-not-exists", isAdded: false };

		const user = await UserModel.findOneAndUpdate(
			{ userId: userId },
			{ $pull: { addedSharks: walletAddress } }
		);

		const deletedData = await InvestorModel.remove({
			walletAddress: walletAddress
		});

		return deletedData.deletedCount > 0
			? { message: "successfully", isDeleted: true }
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
	getOriginalPriceOfToken,
	getTransactionsLength,
	getGainLossOfSharks,
	getGainLossOfCoins,
	getListOfSharkFollowed,
	followWalletOfShark,
	unfollowWalletOfShark,
	addNewShark,
	deleteSharkNotFound
};
