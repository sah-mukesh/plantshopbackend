const router = require('express').Router();
const productController = require("../controller/productControllers");
const { authGuard,authGuardAdmin } = require('../middleware/authGuard');
const  orderController=require("../controller/orderController")

router.post('/create_product', productController.createProduct)

// get all products
router.get("/get_products", productController.getProducts)

//get all products
router.get("/get_products", productController.getAllProducts)

// single product
router.get("/get_product/:id", productController.getSingleProduct)

// update product
router.put("/update_product/:id", productController.updateProduct)

// delete product
//router.delete("/delete_product/:id",authGuardAdmin ,productController.deleteProduct)

router.delete("/delete_product/:id" ,productController.deleteProduct)

router.post("/create_order",orderController.createOrder)
 
router.get("/get_order/:id",orderController.getOrders)


router.post('/sales', productController.createSaleProduct);
router.get('/sales', productController.getAllSaleProducts);
 


module.exports = router;