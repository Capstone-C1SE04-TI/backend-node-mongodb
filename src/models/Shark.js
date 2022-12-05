const mongoose = require("mongoose");
const AutoIncrement = require("mongoose-sequence")(mongoose);

const SharkSchema = new mongoose.Schema(
	{
		coins: {
			type: Object,
			default: {}
		},
		totalAssets: {
			type: Number,
			required: true,
			default: 0
		},
		percent24h: {
			type: Number,
			required: true,
			default: 0
		},
		transactionsHistory: {
			type: Array,
			default: []
		},
		walletAddress: {
			type: String,
			trim: true,
			required: true,
			unique: true,
			default: ""
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
		},
		firstTransactionDate: {
			type: Number,
			default: 0
		},
		totalValueIn: {
			type: Number,
			default: 0
		},
		totalValueOut: {
			type: Number,
			default: 0
		}
	},
	{ versionKey: false }
);

SharkSchema.plugin(AutoIncrement, { inc_field: "sharkId" });

module.exports = mongoose.model("Shark", SharkSchema); 
