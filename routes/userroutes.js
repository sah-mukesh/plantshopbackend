

// import router from express
const router = require("express").Router();
const userController = require("../controller/userControllers");

//all the routes for the user
router.post("/create", userController.createUser);

router.post("/login", userController.loginUser);

router.post("/changePassword", userController.changePassword);

//export
module.exports = router;