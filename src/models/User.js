const mongoose = require("mongoose");
const AutoIncrement = require("mongoose-sequence")(mongoose);

const UserSchema = new mongoose.Schema(
	{
		username: {
			type: String,
			trim: true,
			required: true,
			unique: true,
			minLength: 5,
			maxlength: 16
		},
		email: {
			type: String,
			trim: true,
			required: true,
			unique: true,
			minlength: 16,
			maxlength: 40
		},
		phoneNumber: {
			type: String,
			trim: true,
			minLength: 10,
			maxlength: 10,
			default: ""
		},
		password: {
			type: String,
			trim: true,
			required: true
		},
		fullName: {
			type: String,
			trim: true,
			default: ""
		},
		avatar: {
			type: String,
			trim: true,
			default:
				"https://res.cloudinary.com/dhzbsq7fj/image/upload/v1643101647/avatardefault_92824_aifry9.png"
		},
		website: {
			type: String,
			trim: true,
			default: ""
		},
		premiumAccount: {
			type: Boolean,
			default: false
		},
		walletAddress: {
			type: String,
			trim: true,
			default: null
		},
		sharksFollowed: {
			type: Array,
			default: []
		}
	},
	{ timestamps: true, versionKey: false }
);

UserSchema.plugin(AutoIncrement, { inc_field: "id" });
UserSchema.plugin(AutoIncrement, { inc_field: "userId" });

module.exports = mongoose.model("User", UserSchema);
