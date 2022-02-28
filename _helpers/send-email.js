const nodemailer = require("nodemailer");
const { emailFrom, smtpOptions } = require("../config");

module.exports = sendEmail;

async function sendEmail({ to, subject, html, from = emailFrom }) {
  const transporter = nodemailer.createTransport(smtpOptions);
  await transporter.sendMail({ from, to, subject, html });
}
