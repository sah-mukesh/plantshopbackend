const cloudinary = require("cloudinary");
const Products = require("../model/productModel")
const SaleProduct = require('../model/salesProductModal')

const createProduct = async (req,res) => {
    // step 1 : check incomming data
    console.log(req.body);
    console.log(req.files);

    // step 2 : Destructuring data
    const {
        productName, 
        productPrice,
        productDescription,
        productCategory,
    } = req.body;
    console.log("below text")
    const {productImage} = req.files;
    console.log("below file")

    // step 3 : Validate data
    if(!productName || !productPrice || !productDescription || !productCategory || !productImage){
        return res.json({
            success : false,
            message : "Please fill all the fields"
        })
    }

    try {
        // upload image to cloudinary
        const uploadedImage = await cloudinary.v2.uploader.upload(
            productImage.path,
            {
                folder : "products",
                crop : "scale"
            }
        )

        // Save to database
        const newProduct = new Products({
            productName : productName,
            productPrice : productPrice,
            productDescription : productDescription,
            productCategory : productCategory,
            productImageUrl : uploadedImage.secure_url
        })
        await newProduct.save();
        res.json({
            success : true,
            message : "Product created successfully",
            product : newProduct
        })


        
    } catch (error) {
        console.log(error)
        res.status(500).json({
            success : false,
            message : "Internal server error"
        })
    }

}


// get all products
const getProducts = async (req,res) => {
    try {
        const allProducts = await Products.find({});
        res.json({
            success : true,
            message : "Products fetched successfully",
            products : allProducts
        })
        
    } catch (error) {
        console.log(error);
        res.send("Internal server error")
    }

}

// fetch single product
const getSingleProduct = async (req,res) => {
    const productId = req.params.id;
    try {
        const singleProduct = await Products.findById(productId);
        res.json({
            success : true,
            message : "Single product fetched successfully!",
            product : singleProduct
        })
        
    } catch (error) {
        console.log(error);
        res.send("Internal server error")
    }
}

// update product
const updateProduct = async (req,res) => {
    // step 1 : check incomming data
    console.log(req.body);
    console.log(req.files);

    // destructuring data
    const {
        productName,
        productPrice,
        productDescription,
        productCategory
    } = req.body;
    const {productImage} = req.files;

    // validate data
    if( !productName 
        || !productPrice 
        || !productDescription 
        || !productCategory){
        return res.json({
            success : false,
            message : "Required fields are missing!"
        })
    }

    try {
        // case 1 : if there is image
        if(productImage){
            // upload image to cloudinary
            const uploadedImage = await cloudinary.v2.uploader.upload(
                productImage.path,
                {
                    folder : "products",
                    crop : "scale"
                }
            )

            // make updated json data
            const updatedData = {
                productName : productName,
                productPrice : productPrice,
                productDescription : productDescription,
                productCategory : productCategory,
                productImageUrl : uploadedImage.secure_url
            }

            // find product and update
            const productId = req.params.id;
            await Products.findByIdAndUpdate(productId, updatedData)
            res.json({
                success : true,
                message : "Product updated successfully with Image!",
                updatedProduct : updatedData
            })

        } else {
            // update without image
            const updatedData = {
                productName : productName,
                productPrice : productPrice,
                productDescription : productDescription,
                productCategory : productCategory,
            }

            // find product and update
            const productId = req.params.id;
            await Products.findByIdAndUpdate(productId, updatedData)
            res.json({
                success : true,
                message : "Product updated successfully without Image!",
                updatedProduct : updatedData
            })
        }
        
    } catch (error) {
        res.status(500).json({  
            success : false,
            message : "Internal server error"
        })
    }
}

// delete product
const deleteProduct = async (req,res) =>{
    const productId = req.params.id;

    try {
        await Products.findByIdAndDelete(productId);
        res.json({
            success : true,
            message : "Product deleted successfully!"
        })
        
    } catch (error) {
        res.json({
            success : false,
            message : "Server error!!"
        })
    }
}
const getAllProducts = async (req, res) => {
    try {
      const listOfProducts = await Products.find();
      res.json({
        success: true,
        message: "Products fetched successfully",
        products: listOfProducts,
      });
    } catch (error) {
      console.log(error);
      res.status(500).json("Server Error");
    }
  };


//   for sale product

const createSaleProduct = async (req, res) => {
    console.log(req.body);
    console.log(req.files);

    // step 2 : Destructuring data
    const {
        saleProductName, 
        saleProductPrice,
        saleDiscount,
        saleRating,
    } = req.body;
    console.log("below text")
    const {saleProductImage} = req.files;
    console.log("below file")

    // step 3 : Validate data
    if(!saleProductName || !saleProductPrice || !saleDiscount || !saleRating || !saleProductImage ){
        return res.json({
            success : false,
            message : "Please fill all the fields"
        })
    }
    try {
         // upload image to cloudinary
         const uploadedImage = await cloudinary.v2.uploader.upload(
            saleProductImage.path,
            {
                folder : "sales",
                crop : "scale"
            }
        )

        // Save to database
        const newSalesProduct = new Products({
            saleProductName : saleProductName,
            saleProductPrice : saleProductPrice,
            saleDiscount : saleDiscount,
            saleRating : saleRating,
            salePoductImage : uploadedImage.secure_url
        })
        await newSalesProduct.save();
        res.json({
            success : true,
            message : "Sales Product created successfully",
            product : newSalesProduct
        })
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};

const getAllSaleProducts = async (req, res) => {
    try {
        const saleProducts = await SaleProduct.find();
        res.json({
            success : true,
            message : "Sales Products fetched successfully",
            products : saleProducts
        })    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};


module.exports = {
    createProduct,
    getProducts,
    getSingleProduct,
    updateProduct,
    deleteProduct,
    getAllProducts,
    createSaleProduct,
    getAllSaleProducts,
}

