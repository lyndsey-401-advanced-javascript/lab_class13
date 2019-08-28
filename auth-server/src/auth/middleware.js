'use strict';

const User = require('./users-model.js');

module.exports = (req, res, next) => {
  
  try {
    let [authType, authString] = req.headers.authorization.split(/\s+/);
    
    switch( authType.toLowerCase() ) {
      case 'basic': 
        return _authBasic(authString);
      case 'bearer':
        return _authBearer(authString); //sets up _authBearer authorization
      default: 
        return _authError();
    }
  }
  catch(e) {
    next(e);
  }
  
  
  function _authBasic(str) {
    // str: am9objpqb2hubnk=
    let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
    let bufferString = base64Buffer.toString();    // john:mysecret
    let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
    let auth = {username,password}; // { username:'john', password:'mysecret' }
    
    return User.authenticateBasic(auth)
      .then(user => _authenticate(user) )
      .catch(next);
  }

  //(line 14) similar to authenticateBasic, but starts by validating token
  function _authBearer(authString) {
    return User.authenticateToken(authString)
      .then(user => _authenticate(user) )
      .catch(next);
  }

  function _authenticate(user) {
    if(user) {
      req.user = user;
      req.token = user.generateToken();
      next();
    }
    else {
      _authError();
    }
  }
  
  function _authError() {
    next('Invalid User ID/Password');
  }
  
};
