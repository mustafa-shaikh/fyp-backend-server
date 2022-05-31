const express = require("express");
const router = express.Router();
const Joi = require("joi");
const validateRequest = require("../_middleware/validate-request");
const authorize = require("../_middleware/authorize");
const Role = require("../_helpers/role");
const patientService = require("./patient.service");
const fs = require('fs');
const multer = require("multer");
const pdfParse = require('pdf-parse');


// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     let dir = `/tmp/myuploads/`; // specify the path you want to store file
//     //check if file path exists or create the directory
//     fs.access(dir, function (error) {
//       if (error) {
//         console.log("Directory does not exist.");
//         return fs.mkdir(dir, error => cb(error, dir));
//       } else {
//         console.log("Directory exists.");
//         return cb(null, dir);
//       }
//     });
//   },
//   filename: function (req, file, cb) {
//     cb(null, Date.now() + "-" + file.originalname); // added Date.now() so that name will be unique
//   }
// });
// const uploadFiles = multer({ storage: storage });

// routes
router.post("/register", registerSchema, register);
router.post("/verify-email", verifyEmailSchema, verifyEmail);
router.post("/authenticate", authenticateSchema, authenticate);
router.post("/refresh-token", refreshToken);
router.post("/revoke-token", revokeTokenSchema, revokeToken);
router.post("/forgot-password", forgotPasswordSchema, forgotPassword);
router.post("/reset-password", resetPasswordSchema, resetPassword);
router.get("/hospitals", authorize(Role.Patient), getAllHospitals);
router.get("/:id", getById);
// router.put('/:id', authorize(Role.Patient), updateSchema, update);
router.put("/:id", updateSchema, update);
router.post("/create-case", caseSchema, createCase);
router.put("/update-case/:id", updateCaseSchema, updateCase);
router.get("/cases/:id", getAllCases); //List of Cases
router.get("/hospital/:id", getCaseById); //List of Cases

router.post("/create-appointment", appointmentSchema, createAppointment);
router.post("/send-report", authorize(Role.Patient), sendReport);

// router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken); // not necessary
router.delete("/:id", authorize(), _delete);
// router.post('/', authorize(Role.Patient), createSchema, create);

module.exports = router;

function authenticateSchema(req, res, next) {
  const schema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function authenticate(req, res, next) {
  const { email, password } = req.body;
  const ipAddress = req.ip;
  patientService
    .authenticate({ email, password, ipAddress })
    .then(({ refreshToken, ...patient }) => {
      setTokenCookie(res, refreshToken);
      res.json(patient);
    })
    .catch(next);
}

function refreshToken(req, res, next) {
  const token = req.cookies.pRefreshToken;
  const ipAddress = req.ip;
  patientService
    .refreshToken({ token, ipAddress })
    .then(({ refreshToken, ...patient }) => {
      setTokenCookie(res, refreshToken);
      res.json(patient);
    })
    .catch((next) => {
      const response = {
        isVerified: false,
      };
      res.json(response).status(304);
    });
}

function revokeTokenSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().empty(""),
  });
  validateRequest(req, next, schema);
}

function revokeToken(req, res, next) {
  // accept token from request body or cookie
  const token = req.cookies.pRefreshToken;
  const ipAddress = req.ip;

  if (!token) return res.status(400).json({ message: "Token is required" });

  // // users can revoke their own tokens and patients can revoke any tokens
  // if (!req.user.ownsToken(token) && req.user.role !== Role.Patient) {
  //     return res.status(401).json({ message: 'Unauthorized' });
  // }

  patientService
    .revokeToken({ token, ipAddress })
    .then(() => res.json({ message: "Token revoked" }))
    .catch(next);
}

function registerSchema(req, res, next) {
  const schema = Joi.object({
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref("password")).required(),
    // acceptTerms: Joi.boolean().valid(true).required()
  });
  validateRequest(req, next, schema);
}

function register(req, res, next) {
  patientService
    .register(req.body, req.get("origin"))
    .then(() =>
      res.json({
        message:
          "Registration successful, please check your email for verification instructions",
        status: 200,
      })
    )
    .catch(next);
}

function verifyEmailSchema(req, res, next) {
  const schema = Joi.object({
    pin: Joi.string().required(),
    email: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function verifyEmail(req, res, next) {
  patientService
    .verifyEmail(req.body)
    .then(() =>
      res.json({
        message: "Verification successful, you can now login",
        status: 200,
      })
    )
    .catch(next);
}

function forgotPasswordSchema(req, res, next) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });
  validateRequest(req, next, schema);
}

function forgotPassword(req, res, next) {
  patientService
    .forgotPassword(req.body, req.get("origin"))
    .then(() =>
      res.json({
        message: "Please check your email for password reset instructions",
      })
    )
    .catch(next);
}

function validateResetTokenSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function validateResetToken(req, res, next) {
  patientService
    .validateResetToken(req.body)
    .then(() => res.json({ message: "Token is valid" }))
    .catch(next);
}

function resetPasswordSchema(req, res, next) {
  const schema = Joi.object({
    pin: Joi.string().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref("password")).required(),
  });
  validateRequest(req, next, schema);
}

function resetPassword(req, res, next) {
  patientService
    .resetPassword(req.body)
    .then(() =>
      res.json({ message: "Password reset successful, you can now login" })
    )
    .catch(next);
}

function getAllHospitals(req, res, next) {
  patientService
    .getAllHospitals()
    .then((hospitals) => res.json(hospitals))
    .catch(next);
}

function getById(req, res, next) {
  // users can get their own patient and patients can get any patient
  //authorize all necessary routes
  // if (req.params.id !== req.user.id && req.user.role !== Role.Patient) {
  //     if (req.params.id !== req.user.id && req.user.role !== Role.Patient) {
  //     return res.status(401).json({ message: 'Unauthorized' });
  // }

  patientService
    .getById(req.params.id)
    .then((patient) => (patient ? res.json(patient) : res.sendStatus(404)))
    .catch(next);
}

function appointmentSchema(req, res, next) {
  //temp created in body\
  console.log("params", req.body)
  const schema = Joi.object({
    time: Joi.string().required(),
    doctorId: Joi.string().required(),
    patientId: Joi.string().required(),

  });
  validateRequest(req, next, schema);
}

function createAppointment(req, res, next) {
  patientService
    .createAppointment(req.body)
    .then((patient) => res.json(patient))
    .catch(next);
}







function sendReport(req, res, next) {
  patientService.sendReport(req.user.id, req.body.name)
    .then((x) => res.json(x))
    .catch(next);
}


// uploadFiles.single("file");


// pdfParse(req.file).then(function (data) {

//   // number of pages
//   console.log(data.numpages);
//   // number of rendered pages
//   console.log(data.numrender);
//   // PDF info
//   console.log(data.info);
//   // PDF metadata
//   console.log(data.metadata);
//   // PDF.js version
//   // check https://mozilla.github.io/pdf.js/getting_started/
//   console.log(data.version);
//   // PDF text
//   console.log(data.text);

// });


// function createSchema(req, res, next) {
//     const schema = Joi.object({
//         subject: Joi.string().required(),
//         type: Joi.string().required(),
//         message: Joi.string().required(),
//         password: Joi.string().min(6).required(),
//         confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
//         role: Joi.string().valid(Role.Patient, Role.User).required()
//     });
//     validateRequest(req, next, schema);
// }

// function create(req, res, next) {
//     patientService.create(req.body)
//         .then(patient => res.json(patient))
//         .catch(next);
// }

function caseSchema(req, res, next) {
  //temp created in body
  const schema = Joi.object({
    createdBy: Joi.string().required(),
    caseSubject: Joi.string().required(),
    caseType: Joi.string().required(),
    caseMessage: Joi.string().required(),
    document01: Joi.object({
      documentStatus: Joi.string().required(),
      documentPath: Joi.string().required(),
    }),
    document02: Joi.object({
      documentStatus: Joi.string().required(),
      documentPath: Joi.string().required(),
    }),
    document03: Joi.object({
      documentStatus: Joi.string().required(),
      documentPath: Joi.string().required(),
    }),
  });
  validateRequest(req, next, schema);
}

function createCase(req, res, next) {
  // req.body.createdBy = req.user.id;
  patientService
    .createCase(req.body)
    .then((patient) => res.json(patient))
    .catch(next);
}

function getCaseById(req, res, next) {
  patientService
    .getCaseById(req.params.id)
    .then((casse) => (casse ? res.json(casse) : res.sendStatus(404)))
    .catch(next);
}

function updateCaseSchema(req, res, next) {
  const schema = Joi.object({
    documentStatus: Joi.string().required(),
    documentPath: Joi.string().required(),
    documentTitle: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function updateCase(req, res, next) {
  // req.body.createdBy = req.user.id;
  patientService
    .updateCase(req.params.id, req.body)
    .then((casse) => res.json(casse))
    .catch(next);
}

function updateSchema(req, res, next) {
  const schemaRules = {
    firstName: Joi.string().empty(""),
    lastName: Joi.string().empty(""),
    address: Joi.string().empty(""),
    city: Joi.string().empty(""),
    phone: Joi.string().empty(""),
    imageUrl: Joi.string().empty(""),
    password: Joi.string().min(6).empty(""),
    confirmPassword: Joi.string().valid(Joi.ref("password")).empty(""),
  };

  const schema = Joi.object(schemaRules).with("password", "confirmPassword");
  validateRequest(req, next, schema);
}

function update(req, res, next) {
  patientService
    .update(req.params.id, req.body)
    .then((user) => res.json(user))
    .catch(next);
}

function getAllCases(req, res, next) {
  patientService
    .getAllCases(req.params.id)
    .then((cases) => res.json(cases))
    .catch(next);
}

function _delete(req, res, next) {
  // users can delete their own patient and patients can delete any patient
  if (req.params.id !== req.user.id && req.user.role !== Role.Patient) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  patientService
    .delete(req.params.id)
    .then(() => res.json({ message: "Patient deleted successfully" }))
    .catch(next);
}

// helper functions

function setTokenCookie(res, token) {
  // create cookie with refresh token that expires in 7 days
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };
  res.cookie("pRefreshToken", token, cookieOptions);
}
