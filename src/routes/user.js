const express = require("express");
const router = express.Router();
const UserController = require("../controllers/User");
const { isAuth } = require("../middlewares/authentication");

/**
 * @swagger
 * /user/profile/update:
 *   post:
 *     description: Update user profile
 *     tags: [User]
 *     parameters:
 *      - in: query
 *        name: userId
 *        schema:
 *          type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fullName
 *               - email
 *               - phoneNumber
 *               - website
 *               - avatar
 *             properties:
 *               fullName:
 *                  type: string
 *               email:
 *                  type: string
 *               phoneNumber:
 *                  type: string
 *               website:
 *                  type: string
 *               avatar:
 *                  type: string
 *             example:
 *               fullName: "Huynh Ngoc Hieu"
 *               email: "hieuhn@gmail.com"
 *               phoneNumber: "0366871673"
 *               website: "https://www.britannica.com/biography/Elon-Musk"
 *               avatar: "https://res.cloudinary.com/dhzbsq7fj/image/upload/v1643101647/avatardefault_92824_aifry9.png"
 *     responses:
 *       200:
 *         description: Update user profile successfully
 *       400:
 *         description: Update user profile failed
 */
// router.post("/profile/update", UserController.updateUserProfile);
router.post("/profile/update", isAuth, UserController.updateUserProfile);

/**
 * @swagger
 * /user/profile:
 *   get:
 *     description: Get user profile
 *     tags: [User]
 *     parameters:
 *      - in: query
 *        name: userId
 *        schema:
 *          type: string
 *     responses:
 *       200:
 *         description: Get user profile successfully
 *       400:
 *         description: Get user profile failed
 */
// router.get("/profile", UserController.getUserProfile);
router.get("/profile", isAuth, UserController.getUserProfile);

/**
 * @swagger
 * /user/change-password:
 *   post:
 *     description: Change Password
 *     tags: [User]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - oldPassword
 *               - newPassword
 *               - newConfirmPassword
 *             properties:
 *               email:
 *                  type: string
 *               oldPassword:
 *                  type: string
 *               newPassword:
 *                  type: string
 *               newConfirmPassword:
 *                  type: string
 *             example:
 *               email: "hieuhn@gmail.com"
 *               oldPassword: "12345678"
 *               newPassword: "12345678910"
 *               newConfirmPassword: "12345678910"
 *     responses:
 *       200:
 *         description: Change password successfully
 *       400:
 *         description: Change password failed
 */
// router.post("/change-password", UserController.changePassword);
router.post("/change-password", isAuth, UserController.changePassword);

/**
 * @swagger
 * /user/upgrade-premium-account:
 *   post:
 *     description: Upgrade premium account
 *     tags: [User]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                  type: string
 *             example:
 *               userId: "1"
 *     responses:
 *       200:
 *         description: Upgrade premium account successfully
 *       400:
 *         description: Upgrade premium account failed
 */
// router.post("/upgrade-premium-account", UserController.upgradePremiumAccount);
router.post(
	"/upgrade-premium-account",
	isAuth,
	UserController.upgradePremiumAccount
);

/**
 * @swagger
 * /user/follow-shark-wallet:
 *   post:
 *     description: Follow shark wallet
 *     tags: [User]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *               - sharkId
 *             properties:
 *               userId:
 *                  type: string
 *               sharkId:
 *                  type: string
 *             example:
 *               userId: "1"
 *               sharkId: "1"
 *     responses:
 *       200:
 *         description: Follow shark wallet successfully
 *       400:
 *         description: Follow shark wallet failed
 */
// router.post("/follow-shark-wallet", UserController.followSharkWallet);
router.post("/follow-shark-wallet", isAuth, UserController.followSharkWallet);

/**
 * @swagger
 * /user/unfollow-shark-wallet:
 *   post:
 *     description: Unfollow shark wallet
 *     tags: [User]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *               - sharkId
 *             properties:
 *               userId:
 *                  type: string
 *               sharkId:
 *                  type: string
 *             example:
 *               userId: "1"
 *               sharkId: "1"
 *     responses:
 *       200:
 *         description: Unfollow shark wallet successfully
 *       400:
 *         description: Unfollow shark wallet failed
 */
// router.post("/unfollow-shark-wallet", UserController.unfollowSharkWallet);
router.post(
	"/unfollow-shark-wallet",
	isAuth,
	UserController.unfollowSharkWallet
);

/**
 * @swagger
 * /user/list-followed-shark:
 *   get:
 *     description: Get list of shark followers
 *     tags: [User]
 *     parameters:
 *      - in: query
 *        name: userId
 *        schema:
 *          type: string
 *     responses:
 *       200:
 *         description: Get list of shark followers successfully
 *       400:
 *         description: Get list of shark followers failed
 */
// router.get("/list-followed-shark", UserController.getSharkFollowed);
router.get("/list-followed-shark", isAuth, UserController.getSharkFollowed);

module.exports = router;
