const jwt = require('express-jwt');
const { secret } = require('../config.js');
const db = require('../_helpers/db');

module.exports = authorize;

function authorize(roles = []) {

    // roles param can be a single role string (e.g. Role.User or 'User') 
    // or an array of roles (e.g. [Role.Admin, Role.User] or ['Admin', 'User'])
    if (typeof roles === 'string') {
        roles = [roles];
    }
    return [
        // authenticate JWT token and attach user to request object (req.user)
        jwt({ secret, algorithms: ['HS256'] }),
        
        // authorize based on user role
        async (req, res, next) => {

            
            let account ;
            let refreshTokens;
            
            if(roles.includes("Hospital"))
            {
                
                account = await db.Hospital.findById(req.user.id);
                refreshTokens = await db.HospitalRefreshToken.find({ hospital: account.id });
                
            }
            if (roles.includes("Doctor"))
            {
                account = await db.Doctor.findById(req.user.id);
                refreshTokens = await db.DoctorRefreshToken.find({ doctor: account.id });
                
            }
            if (roles.includes("Patient"))
            {
                account = await db.Patient.findById(req.user.id);
                refreshTokens = await db.PatientRefreshToken.find({ patient: account.id });
                
            }
            
            if (!account || (roles.length && !roles.includes(account.role))) {
                // account no longer exists or role not authorized
                return res.status(401).json({ message: 'Unauthorized' });
            }

            // authentication and authorization successful
            req.user.role = account.role;
            req.user.ownsToken = token => !!refreshTokens.find(x => x.token === token);
            next();
        }
    ];
}