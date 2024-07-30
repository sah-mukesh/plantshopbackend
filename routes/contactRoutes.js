const route=require ('express').Router();
 
const contactcontroller =require("../controller/contactController")
// const { createContact } = require('../controllers/contactcontroller');
 
 
 
route.post("/createContact", contactcontroller.createContact)
 
// route.post("/createcontact", contactcontroller.createContact)
route.delete("/deleteContact/:id", contactcontroller.deleteContactById)
 
 
route.get('/getAllContact', contactcontroller.getAllContact)
 
 
route.get("/get_pagination", contactcontroller.getpagination)
 
module.exports=route;
 
 
 