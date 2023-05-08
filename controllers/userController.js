const User = require("../models/userModel");
const Tokens = require("../models/token.model")
const bcrypt = require("bcrypt");
const crypto = require('crypto');
// const crypto =require("crypto-js")
const { sendEmail } = require('../utilities/sendEmail');

module.exports.login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user)
      return res.json({ msg: "Incorrect Username or Password", status: false });
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.json({ msg: "Incorrect Username or Password", status: false });
    delete user.password;
    return res.json({ status: true, user });
  } catch (ex) {
    next(ex);
  }
};

module.exports.register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const usernameCheck = await User.findOne({ username });
    if (usernameCheck)
      return res.json({ msg: "Username already used", status: false });
    const emailCheck = await User.findOne({ email });
    if (emailCheck)
      return res.json({ msg: "Email already used", status: false });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      email,
      username,
      password: hashedPassword,
    });
    delete user.password;
    return res.json({ status: true, user });
  } catch (ex) {
    next(ex);
  }
};

module.exports.forgotPassword = async (req, res) => {
  try{
      const { email } = req.body;
      if(!email){
          return res.status(400).send({message: "Email is mandatory"});
      }
      const user = await User.findOne({email : email});

      if(!user){
          return res.status(400).send({message: 'User does not exist'});
      };

      let token = await Tokens.findOne({userId: user._id});

      if(token){
          await token.deleteOne();
      }

      let newToken = crypto.randomBytes(32).toString('hex'); //Encryption

      const hashedToken = await bcrypt.hash(newToken, 10);

      const tokenPayload = new Tokens({userId: user._id, token: hashedToken, createdAt: Date.now()});

      await tokenPayload.save();
 
      // const link = `https://main--pasword-flow.netlify.app/passwordReset?token=${newToken}&id=${user._id}`;
      const link = `http://localhost:4000/api/auth//passwordReset?token=${newToken}&id=${user._id}`;

      await sendEmail(user.email, 'Password Reset Link', {name: user.name, link: link});
      
      return res.status(200).send({message: 'Email has been sent successfully.'})

  }catch(error){
      console.log('Error: ', error)
      res.status(500).send({message: "Internal Server Error"});
  }
}


module.exports.resetPassword = async (req, res) => {
  const {userId, token, password} = req.body;

  let resetToken = await Tokens.findOne({userId: userId});
  if(!resetToken){
      return res.status(401).send({message: 'Invalid or expired token.'})
  }

  const isValid = await bcrypt.compare(token, resetToken.token);

  if(!isValid){
      return res.status(400).send({message: 'Invalid Token'});
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  User.findByIdAndUpdate({_id: userId}, {$set: {password: hashedPassword}}, (err, data) => {
      if(err){
          return res.status(400).send({message: 'Error while resetting password.'})
      }
  });

  await resetToken.deleteOne();

  return res.status(200).send({message: 'Password has been reset successfully.'})

}

module.exports.getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find({ _id: { $ne: req.params.id } }).select([
      "email",
      "username",
      "avatarImage",
      "_id",
    ]);
    return res.json(users);
  } catch (ex) {
    next(ex);
  }
};

module.exports.setAvatar = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const avatarImage = req.body.image;
    const userData = await User.findByIdAndUpdate(
      userId,
      {
        isAvatarImageSet: true,
        avatarImage,
      },
      { new: true }
    );
    return res.json({
      isSet: userData.isAvatarImageSet,
      image: userData.avatarImage,
    });
  } catch (ex) {
    next(ex);
  }
};

module.exports.logOut = (req, res, next) => {
  try {
    if (!req.params.id) return res.json({ msg: "User id is required " });
    onlineUsers.delete(req.params.id);
    return res.status(200).send();
  } catch (ex) {
    next(ex);
  }
};
