const mongoose = require("mongoose");

const TagSchema = new mongoose.Schema(
	{
		id: {
			type: Number,
			required: true,
			unique: true
		},
		name: {
			type: String,
			trim: true,
			required: true,
			unique: true
		}
	},
	{ versionKey: false }
);

module.exports = mongoose.model("Tag", TagSchema);
