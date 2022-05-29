const dotenv = require("dotenv");
const path = require("path");

dotenv.config({
  path: path.resolve(__dirname, `.env.${process.env.NODE_ENV}`),
});
module.exports = {
  port: process.env.PORT || 3000,
  morganEnv: process.env.MORGAN_ENV,
  nodeEnv: process.env.NODE_ENV,

  connectionString: process.env.CONNECTION_STRING,
  secret: process.env.SECRET,

  chainUsername: process.env.CHAIN_USERNAME,
  chainPassword: process.env.CHAIN_PASSWORD,
  chainUri: process.env.CHAIN_URI,
  chainStatus: process.env.CHAIN_STATUS
    ? process.env.CHAIN_STATUS
    : "disconnected",

  modelUri: process.env.MODEL_URI,

  emailFrom: process.env.MAIL_FROM,
  smtpOptions: {
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  },
};
