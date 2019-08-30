'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', function(next) {
  bcrypt.hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});



//if this route has an auth header with a value of bearer, the token is passed here
users.statics.authenticateToken = function(token) {
  const decryptedToken = jwt.verify(token, process.env.SECRET || 'secret');
  const query = {_id: decryptedToken.id};
  
  //check if decrypted token is already in token holding data structure
  
  //add decrypted token to token holding data structure
  
  return this.findOne(query);
};

//this is from code review thursday (8/29) morning
users.statics.authenticateToken = function (token) {
  if (process.env.REMEMBER === 'yes') {
    const decryptedToken = jwt.verify(token, process.env.SECRET || 'secret');
    const query = {_id: decryptedToken.id}
    return this.findOne(query);
  } else {
    if (previousToken.includes(token) ){
      throw new Error('invalid token');
    } else {
      previousToken.push(token);
      const decryptedToken = jwt.verify(token, process.env.SECRET || 'secret');
      const query = {_id: decryptedToken.id};
      return this.findOne(query);
    }
  }
};


users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
    .then(user => {
      if( !user ) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch( error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({username, password, email});
    });

};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password) )
    .catch(error => {throw error;});
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};

users.methods.generateToken = function() {
  
  let token = {
    id: this._id, 
    role: this.role,
  };
  
  //secretOrPrivateKey
  //{expiresIn should tell the key to expire after 15minutes (or 900seconds)}
  return jwt.sign(token, process.env.SECRET, {expiresIn: 900});
  //returns json web token as a string
};

module.exports = mongoose.model('users', users);

