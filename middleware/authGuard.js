const jwt = require('jsonwebtoken')

const authGuard = (req, res, next) =>{
    //Check if auth header is present
    const authHeader = req.headers.authorization;
    if(!authHeader){
        return res.json({
            success : false,
            message : "Authorization header missing!"
        })
    }

    //split auth header and get token
    //Format : Bearer sdflhwerewr23423ljsdf
    const token = authHeader.split(' ')[1];
    if(!token){
        return res.json({
            success : false,
            message : "Token missing!"
        })
    }

    //verify token
    try{
        const decodedData = jwt.verify(token, process.env.JWT_SECRET)
        req.user = decodedData
        next();
    }catch(error){
        return res.json({
            success : false,
            message : "Invalid token!"
        })
    }
}

// todo: Admin token authentication
const authGuardAdmin = (req, res, next) =>{
    //Check if auth header is present
    const authHeader = req.headers.authorization;
    if(!authHeader){
        return res.json({
            success : false,
            message : "Authorization header missing!"
        })
    }

    //*split auth header and get token
    //*Format : Bearer sdflhwerewr23423ljsdf
    const token = authHeader.split(' ')[1];
    if(!token){
        return res.json({
            success : false,
            message : "Token missing!"
        })
    }

    //*verify token
    try{
        const decodedData = jwt.verify(token, process.env.JWT_SECRET)
        req.user = decodedData
        console.log(req.user)
        if(!req.user.isAdmin){
            return res.json({
                success : false,
                message: "Permission denied"
            })
        }
        next();
    }catch(error){
        return res.json({
            success : false,
            message : "Invalid token!"
        })
    }
}

module.exports = {authGuard, authGuardAdmin};

// session handle 