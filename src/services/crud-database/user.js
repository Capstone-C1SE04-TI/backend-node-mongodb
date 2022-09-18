const database = require("../../configs/connect-database");
const firebase = require("firebase-admin");
const { randomFirestoreDocumentId } = require("../../helpers");

const getUserByUsername = async (username) => {
    let user;
    const users = await database.collection("users")
        .where("username", "==", username)
        .get();

    users.forEach((doc) => {
        user = doc.data();
    });

    return user;
};

const getUserByEmail = async (email) => {
    let user;

    const users = await database
        .collection("users")
        .where("email", "==", email)
        .get();

    users.forEach((doc) => {
        user = doc.data();
        user.docId = doc.id;
    });

    return user;
};

const createNewUser = async ({ username, email, phoneNumber, hashPassword }) => {
    const usersLength = await getUsersLength();
    const userId = usersLength ? usersLength + 1 : 1;

    const currentTimestamp = firebase.firestore.Timestamp.now();
    const docId = randomFirestoreDocumentId();

    const newUserInfo = {
        userId: userId,
        username: username,
        email: email,
        phoneNumber: phoneNumber,
        password: hashPassword,
        createdDate: currentTimestamp,
        updatedDate: currentTimestamp,
    };

    await database.collection("users").doc(docId).set(newUserInfo);
};

const updateUserConfirmationCode = async (docId, code) => {
    const user = database.collection("users").doc(docId);

    await user.update({ confirmationCode: code });

    return user;
};

const checkExistedUsername = async (username) => {
    isExistedUsername = false;

    const users = await database.collection("users").get();
    users.forEach((doc) => {
        if (doc.get("username") === username) {
            isExistedUsername = true;
        }
    });

    return isExistedUsername;
};

const checkExistedEmail = async (email) => {
    isExistedEmail = false;

    const users = await database.collection("users").get();
    users.forEach((doc) => {
        if (doc.get("email") === email) {
            isExistedEmail = true;
        }
    });

    return isExistedEmail;
};

const getPasswordByUsername = async (username) => {
    let hashPassword;

    const users = await database.collection("users")
        .where("username", "==", username)
        .get();

    users.forEach((doc) => {
        hashPassword = doc.get("password");
    });

    return hashPassword;
};

const getListOfUsers = async (page = 1) => {
    let usersList = [];

    const LIMIT_ITEM = 100;
    const startIndex = page === 1 ? 1 : (page * LIMIT_ITEM) + 1

    const users = await database.collection("users")
        .orderBy("userId", "asc")
        .startAt(startIndex)
        .limit(LIMIT_ITEM)
        .get();

    users.forEach((doc) => {
        usersList.push(doc.data());
    });

    return usersList;
}

const getUsersLength = async () => {
    let usersLength = 0;
    const users = await database.collection("users").get();

    users.forEach((doc) => usersLength++);

    return usersLength;
}


const getListOfCoins = async (page = 1) => {
    let coinsList = [];

    const LIMIT_ITEM = 100;
    const startIndex = page === 1 ? 1 : (page * LIMIT_ITEM) + 1

    const coins = await database.collection("tokens")
        .orderBy("id", "asc")
        .startAt(startIndex)
        .limit(LIMIT_ITEM)
        .get();

    coins.forEach((doc) => {
        coinsList.push(doc.data());
    });

    return coinsList;
}

module.exports = {
    getUserByUsername,
    getUserByEmail,
    createNewUser,
    updateUserConfirmationCode,
    checkExistedUsername,
    checkExistedEmail,
    getPasswordByUsername,
    getListOfUsers,
    getUsersLength,
    getListOfCoins
};
