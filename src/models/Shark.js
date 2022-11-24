const mongoose = require("mongoose");

const SharkSchema = new mongoose.Schema(
	{
		id: {
			type: Number,
			required: true,
			unique: true
		},
		coins: {
			type: Object,
			default: {}
		},
		totalAssets: {
			type: Number,
			required: true
		},
		percent24h: {
			type: Number,
			required: true
		},
		transactionsHistory: {
			type: Array,
			default: []
		},
		walletAddress: {
			type: String,
			trim: true,
			required: true,
			unique: true
		},
		cryptos: {
			type: Array,
			default: []
		},
		historyDatas: {
			type: Array,
			default: []
		},
		followers: {
			type: Array,
			default: []
		}
	},
	{ versionKey: false }
);

module.exports = mongoose.model("Shark", SharkSchema);
