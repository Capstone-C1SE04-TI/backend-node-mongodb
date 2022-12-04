const mongoose = require("mongoose");
const AutoIncrement = require("mongoose-sequence")(mongoose);

const TestSchema = new mongoose.Schema(
	{
		coins: {
			type: Object
		},
		
    },
	{ versionKey: false }
);

// SharkSchema.plugin(AutoIncrement, { inc_field: "sharkId" });

module.exports = mongoose.model("Investor", TestSchema); 
