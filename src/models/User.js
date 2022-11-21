const mongoose = require("mongoose");
const { ObjectId } = mongoose.Schema.Types;

const UserSchema = new mongoose.Schema(
	{
		_id: { type: ObjectId },
		id: {
			type: Number,
			required: true,
			unique: true
		},
		userId: {
			type: Number,
			required: true,
			unique: true
		},
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
		sharksFollowed: {
			type: Array,
			default: []
		},
		accessToken: {
			type: String,
			default: ""
		},
		refreshAccessToken: {
			type: String,
			default: ""
		},
		createdDate: { type: Object, default: {} },
		updatedDate: { type: Object, default: {} }
	},
	{ timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);
