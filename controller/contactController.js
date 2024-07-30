const Contact = require("../model/contactModel");
const Users = require("../model/usermodel");
 
const bcrypt = require('bcrypt');
 
const CryptoJS = require("crypto-js");
 
const secretKey = "your_secret_key"; // Replace with your secret key
 
const createContact = async (req, res) => {
  // step 1: Check if data is coming or not
  console.log(req.body);
 
  // step 2: Destructure the data
  const { name, email, message } = req.body;
 
  // step 3: Validate the incoming data
  if (!name || !email || !message) {
    return res.json({
      success: false,
      message: "Please fill all the fields.",
    });
  }
 
  try {
    // step 4: Encrypt the data using AES
    const encryptedName = CryptoJS.AES.encrypt(name, secretKey).toString();
    const encryptedEmail = CryptoJS.AES.encrypt(email, secretKey).toString();
    const encryptedMessage = CryptoJS.AES.encrypt(message, secretKey).toString();
 
    // step 5: Create the contact object with encrypted data
    const createContact = new Contact({
      name: encryptedName,
      email: encryptedEmail,
      message: encryptedMessage,
    });
 
    // step 6: Save the contact and respond
    await createContact.save();
    res.status(200).json({
      success: true,
      message: "Contact created successfully.",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json("Server Error");
  }
};
 
 
 
const getAllContact = async (req, res) => {
  console.log("Get all contact");
 
  try {
    const contacts = await Contact.find();
 
    if (!contacts || contacts.length === 0) {
      console.log("No contact found");
      return res.json({
        success: false,
        message: "No contact found",
      });
    } else {
      // Decrypt each contact's data
      const decryptedContacts = contacts.map(contact => {
        try {
          return {
            _id: contact._id,
            name: CryptoJS.AES.decrypt(contact.name, secretKey).toString(CryptoJS.enc.Utf8),
            email: CryptoJS.AES.decrypt(contact.email, secretKey).toString(CryptoJS.enc.Utf8),
            message: CryptoJS.AES.decrypt(contact.message, secretKey).toString(CryptoJS.enc.Utf8),
            __v: contact.__v
          };
        } catch (error) {
          console.error("Failed to decrypt contact data:", error);
          return {
            _id: contact._id,
            name: "Decryption Error",
            email: "Decryption Error",
            message: "Decryption Error",
            __v: contact.__v
          };
        }
      });
 
      return res.json({
        success: true,
        message: "Contacts found",
        data: decryptedContacts,
      });
    }
  } catch (error) {
    console.error("Error occurred", error);
    return res.json({
      success: false,
      message: "Error occurred",
    });
  }
};
// Pagnation
const getpagination = async (req, res) => {
  // step:1 == get pageNo form froentend
  const requestPage = req.query.page;
 
  // step 2: Restult for per page
  // skiping = not showing same value in diff pages
  // no skiping
 
  const resultPerPage = 2;
 
  try {
    const user = await await Users.find({})
      .skip((requestPage - 1) * resultPerPage)
      .limit(resultPerPage);
 
    // if their os no user
    if (user.length === 0) {
      return res.json({
        success: false,
        message: "No contact found",
      });
    }
    res.json({
      success: true,
      user: user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "server Error",
    });
  }
};
const deleteContactById = async (req, res) => {
  console.log("user id: " + req.params.id); // Use req.params.id consistently
  try {
    const deleteUser = await Contact.findByIdAndDelete(req.params.id);
 
    if (!deleteUser) {
      return res.json({
        success: false,
        message: "Meaage not found!",
      });
    }
 
    res.json({
      success: true,
      message: "Message deleted successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};
 
module.exports = {
  createContact,
  getAllContact,
  getpagination,
  deleteContactById,
};