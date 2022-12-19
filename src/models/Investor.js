const mongoose = require("mongoose");
const AutoIncrement = require("mongoose-sequence")(mongoose);

const InvestorSchema = new mongoose.Schema(
	{
		isShark: {
			type: Boolean,
			default: false
		},
		coins: {
			type: Object,
			default: {}
		},
		totalAssets: {
			type: String,
			default: "0"
		},
		totalValueIn: {
			type: String,
			default: "0"
		},
		totalValueOut: {
			type: String,
			default: "0"
		},
		percent24h: {
			type: Number,
			default: 0
		},
		transactionsHistory: {
			type: Array,
			default: []
		},
		walletAddress: {
			type: String,
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
		}
	},
	{ versionKey: false }
);

InvestorSchema.plugin(AutoIncrement, { inc_field: "sharkId" });

module.exports = mongoose.model("Investor", InvestorSchema);
