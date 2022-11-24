const _ = require("lodash");
const {
	getListOfCoinsAndTokens,
	getListOfSharks,
	getListOfTags,
	getListReducingCoinsAndTokens,
	getListTrendingCoins,
	getListTrendingTokens,
	getCoinOrTokenDetails,
	getListCryptosOfShark,
	getTransactionsOfAllSharks,
	getListTransactionsOfShark,
	getTransactionsLength,
	getGainLossOfSharks,
	getGainLossOfCoins,
	getTradeTransactionHistoryOfShark
} = require("../services/crud-database/user");

function DisplayController() {
	this.getCoinsAndTokens = async (req, res, next) => {
		await getListOfCoinsAndTokens()
			.then((datas) =>
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
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getReducingCoinsAndTokens = async (req, res, next) => {
		await getListReducingCoinsAndTokens()
			.then((datas) =>
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
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getTrendingCoins = async (req, res, next) => {
		await getListTrendingCoins()
			.then((datas) =>
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
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getTrendingTokens = async (req, res, next) => {
		await getListTrendingTokens()
			.then((datas) =>
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
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getCoinOrTokenDetails = async (req, res, next) => {
		if (!req.query.symbol) symbol = null;
		else {
			const symbolCheck = _.toString(req.query.symbol).toUpperCase();
			if (_.isNaN(symbolCheck)) symbol = undefined;
			else symbol = symbolCheck;
		}

		await getCoinOrTokenDetails(symbol)
			.then((data) =>
				Object.entries(data).length === 0
					? res.status(400).json({
							message: "failed-symbol-invalid",
							error: "symbol-invalid",
							data: {}
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							data: data
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					data: {}
				})
			);
	};

	this.getSharks = async (req, res, next) => {
		const {userId} = req.query;
		await getListOfSharks(userId)
			.then((datas) =>
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
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getCryptosOfShark = async (req, res, next) => {
		let sharkId = req.query.sharkId;

		if (!sharkId) sharkId = null;
		else {
			const idCheck = _.toNumber(sharkId);
			if (_.isNaN(idCheck)) sharkId = undefined;
			else sharkId = idCheck;
		}

		await getListCryptosOfShark(sharkId)
			.then((datas) =>
				datas === -1
					? res.status(400).json({
							message: "failed-sharkid-invalid",
							error: "sharkid-invalid",
							datas: [],
							datasLength: 0
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datas: datas,
							datasLength: datas.length
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datas: [],
					datasLength: 0
				})
			);
	};

	this.getTransactionsOfShark = async (req, res, next) => {
		let sharkId = req.query.id;

		if (!sharkId) sharkId = null;
		else {
			const idCheck = _.toNumber(sharkId);
			if (_.isNaN(idCheck)) sharkId = undefined;
			else sharkId = idCheck;
		}

		await getListTransactionsOfShark(sharkId)
			.then((datas) =>
				!_.isArray(datas)
					? res.status(400).json({
							message: "failed-sharkid-invalid",
							error: "sharkid-invalid",
							datas: [],
							datasLength: 0
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datas: datas,
							datasLength: datas.length
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datas: [],
					datasLength: 0
				})
			);
	};

	this.getListTransactionsLength = async (req, res, next) => {
		await getTransactionsLength()
			.then((data) =>
				data === 0
					? res.status(400).json({
							message: "failed-listtransaction-not-exist",
							error: "listtransaction-not-exist",
							data: 0
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							data: data
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					data: 0
				})
			);
	};

	this.getListTransactionsOfAllSharks = async (req, res, next) => {
		let page = req.query.page;

		if (!page) page = null;
		else {
			const numberCheck = _.toNumber(page);
			if (_.isNaN(numberCheck)) page = undefined;
			else page = numberCheck;
		}

		await getTransactionsOfAllSharks(page)
			.then((datas) =>
				!_.isArray(datas)
					? res.status(400).json({
							message: "failed-listtransaction-not-exist",
							error: "listtransaction-not-exist",
							datasLength: 0,
							datas: []
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datasLength: datas.length,
							datas: datas
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getTradeTransactionHistory = async (req, res, next) => {
		let { sharkId, coinSymbol } = req.query;

		if (!sharkId) sharkId = null;
		else {
			if (isNaN(sharkId)) sharkId = undefined;
			else sharkId = Number(sharkId);
		}

		await getTradeTransactionHistoryOfShark(sharkId, coinSymbol)
			.then((data) =>
				data.message === "success"
					? res.status(200).json({
							message: "successfully",
							error: null,
							datas: data.data,
							datasLength: data.data.length
					  })
					: res.status(400).json({
							message: data.message,
							error: data.message,
							datas: null,
							datasLength: 0
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datas: null,
					datasLength: 0
				})
			);
	};

	this.getGainLossOfSharks = async (req, res, next) => {
		let isLoss = false;
		if (!req.query.isLoss) isLoss = false;
		else isLoss = req.query.isLoss === "true";

		await getGainLossOfSharks(isLoss)
			.then((datas) =>
				!_.isArray(datas)
					? res.status(400).json({
							message: "failed-listgainloss-invalid",
							error: "listgainloss-invalid",
							datasLength: 0,
							datas: []
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datasLength: datas.length,
							datas: datas
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getGainLossOfCoins = async (req, res, next) => {
		let isLoss = false;

		if (!req.query.isLoss) isLoss = false;
		else isLoss = req.query.isLoss === "true";

		await getGainLossOfCoins(isLoss)
			.then((datas) =>
				!_.isArray(datas)
					? res.status(400).json({
							message: "failed-listgainloss-invalid",
							error: "listgainloss-invalid",
							datasLength: 0,
							datas: []
					  })
					: res.status(200).json({
							message: "successfully",
							error: null,
							datasLength: datas.length,
							datas: datas
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};

	this.getTags = async (req, res, next) => {
		await getListOfTags()
			.then((datas) =>
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
					  })
			)
			.catch((error) =>
				res.status(400).json({
					message: "failed",
					error: error,
					datasLength: 0,
					datas: []
				})
			);
	};
}

module.exports = new DisplayController();
