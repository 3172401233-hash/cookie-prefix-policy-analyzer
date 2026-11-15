'use strict';

const { parseSetCookie } = require('./src/parse');
const { CookieJar } = require('./src/jar');
const model = require('./src/model');

module.exports = {
  parseSetCookie,
  CookieJar,
  isIPAddress: model.isIPAddress,
  domainMatch: model.domainMatch,
  pathMatch: model.pathMatch,
  defaultPath: model.defaultPath,
};
