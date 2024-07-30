// importing
const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./database/db');
const cors = require('cors');
const cloudinary = require('cloudinary');
const acceptMultimedia = require('connect-multiparty');
const https = require('https');
const fs = require('fs');

// Making express app
const app = express();

// dotenv config
dotenv.config();

// cloudinary config

          
cloudinary.config({ 
  cloud_name: 'dx5g3awwp', 
  api_key: '655191446113931', 
  api_secret: 'gwawBXdmtX5dxWJALfDIKLp5dp8'
});

app.use(acceptMultimedia())

// cors config to accept request from frontend
const corsOptions = {
    origin: true,
    credentials: true,
    optionSuccessStatus: 200
};
app.use(cors(corsOptions))

// mongodb connection
connectDB();

// Accepting json data
app.use(express.json());

// creating test route
app.get("/test", (req,res) => {
    res.status(200).json("Hello from server");
})

// user routes
app.use('/api/user', require('./routes/userroutes'))
// our actual routes
// http://localhost:5000/api/user/create
// http://localhost:5000/api/user/login

// CREATE A ROUTE FOR PRODUCTS
app.use("/api/product", require("./routes/productRoutes"))

app.use('/api', require("./routes/productRoutes"));
app.use("/api/admin", require("./routes/contactRoutes"));

// app.use("/api/product", require)


// defining port
// const PORT = process.env.PORT;
// // run the server
// app.listen(PORT, ()=>{
//     console.log(`Server is running on port ${PORT}`)
// })
const options = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
  };
   
  const PORT = process.env.PORT || 5000;
  https.createServer(options, app).listen(PORT, () => {
    console.log(`HTTPS Server is running on port ${PORT}`);
  });


// make a POST route in userRoutes.js
// make a function for login and export it
// test in postman'
module.exports=app;