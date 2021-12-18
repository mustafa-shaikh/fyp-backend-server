
const dotenv = require('dotenv');
dotenv.config();


module.exports = {
    MONGODB_URI: process.env.MONGODB_URI,
    connectionString: process.env.CONNECTIONSTRING,
    secret: process.env.SECRET,
    emailFrom: "mustafa@fyp.com",
    smtpOptions: {
        host: "smtp.ethereal.email",
        port: 587,
        auth: {
            user: "guadalupe.rogahn65@ethereal.email",
            pass: "FXcVjQfENy8BXR5CKw"
        }
    }
}