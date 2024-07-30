const router = require("express").Router();
const orderController = require("../controllers/ordercontroller");
 

router.post("/createOrder", orderController.createOrder);
 
// router.get("/createOrder", orderController.createOrder);
 
router.get("/get_order/:id", orderController.getOrders);
 
module.exports = router;