const { secret, mondToken } = require("../config");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fetch = require("node-fetch");
const sendEmail = require("../_helpers/send-email");
const db = require("../_helpers/db");
const Role = require("../_helpers/role");
const { func } = require("joi");

module.exports = {
  register, //signUp
  verifyEmail, //pin validation
  authenticate, //signIn

  refreshToken, //session management
  revokeToken, //logout
  forgotPassword, // pin sent for password reset
  resetPassword, //confirm pin sent by email and set new password
  getById, //change it to fetch lawyer of specific case
  update, // update own profile
  createCase,
  updateCase,
  getAllCases,
  getCaseById,
  createAppointment,

  validateResetToken, /// necessary
  getAllHospitals,
  create,
  delete: _delete,
};

async function authenticate({ email, password, ipAddress }) {
  const patient = await db.Patient.findOne({ email });

  if (
    !patient ||
    !patient.isVerified ||
    !bcrypt.compareSync(password, patient.passwordHash)
  ) {
    throw "Email or password is incorrect";
  }

  // authentication successful so generate jwt and refresh tokens
  const jwtToken = generateJwtToken(patient);
  const refreshToken = generateRefreshToken(patient, ipAddress);

  // save refresh token
  await refreshToken.save();

  // return basic details and tokens
  return {
    ...basicDetails(patient),
    jwtToken,
    refreshToken: refreshToken.token,
  };
}

async function refreshToken({ token, ipAddress }) {
  const refreshToken = await getRefreshToken(token);
  const { patient } = refreshToken;

  // replace old refresh token with a new one and save
  const newRefreshToken = generateRefreshToken(patient, ipAddress);
  refreshToken.revoked = Date.now();
  refreshToken.revokedByIp = ipAddress;
  refreshToken.replacedByToken = newRefreshToken.token;
  await refreshToken.save();
  await newRefreshToken.save();

  // generate new jwt
  const jwtToken = generateJwtToken(patient);

  // return basic details and tokens
  return {
    ...basicDetails(patient),
    jwtToken,
    refreshToken: newRefreshToken.token,
  };
}

async function revokeToken({ token, ipAddress }) {
  const refreshToken = await getRefreshToken(token);

  // revoke token and save
  refreshToken.revoked = Date.now();
  refreshToken.revokedByIp = ipAddress;
  await refreshToken.save();
}

async function register(params, origin) {
  // validate
  // if (await db.Patient.findOne({ email: params.email })) {
  //     // send already registered error in email to prevent patient enumeration
  //     return await sendAlreadyRegisteredEmail(params.email, origin);
  // }

  if (
    await db.Patient.findOne({
      $and: [
        {
          email: params.email,
        },
        {
          verified: { $exists: true },
        },
      ],
    })
  ) {
    throw "Email already registered";
  }

  // create patient object
  await db.Patient.findOneAndRemove({ email: params.email });
  const patient = new db.Patient(params);
  patient.role = Role.Patient;
  patient.verified = Date.now();
  patient.passwordHash = hash(params.password);
  await patient.save();
}

async function verifyEmail({ pin, email }) {
  const patient = await db.Patient.findOne({
    $and: [
      {
        email: email,
      },
      {
        verificationToken: pin,
      },
    ],
  });

  if (!patient) throw "Verification failed";

  patient.verified = Date.now();
  patient.verificationToken = undefined;
  await patient.save();
}

async function forgotPassword({ email }, origin) {
  const patient = await db.Patient.findOne({ email });

  // always return ok response to prevent email enumeration
  if (!patient) return;

  // create reset token that expires after 24 hours
  patient.resetToken = {
    token: randomTokenPin(),
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  };
  await patient.save();

  // send email
  await sendPasswordResetEmail(patient, origin);
}

async function validateResetToken({ token }) {
  const patient = await db.Patient.findOne({
    "resetToken.token": token,
    "resetToken.expires": { $gt: Date.now() },
  });

  if (!patient) throw "Invalid token";
}

async function resetPassword({ pin, password }) {
  const patient = await db.Patient.findOne({
    "resetToken.token": pin,
    "resetToken.expires": { $gt: Date.now() },
  });

  if (!patient) throw "Invalid token";

  // update password and remove reset token
  patient.passwordHash = hash(password);
  patient.passwordReset = Date.now();
  patient.resetToken = undefined;
  await patient.save();
}

async function getAllHospitals() {
  const hospitals = await db.Hospital.find();
  return hospitals.map((x) => hospitalDetails(x));
}

async function getById(id) {
  const patient = await getPatient(id);
  return basicDetails(patient);
}

async function create(params) {
  // validate
  if (await db.Patient.findOne({ email: params.email })) {
    throw 'Email "' + params.email + '" is already registered';
  }

  const patient = new db.Patient(params);
  patient.verified = Date.now();

  // hash password
  patient.passwordHash = hash(params.password);

  // save patient
  await patient.save();

  return basicDetails(patient);
}

async function createCase(params) {
  const newCase = new db.Case(params);
  // save patient
  await newCase.save();

  return caseDetails(newCase);
}

async function createAppointment(params) {
  console.log("okay", params)
  const newAppointment = new db.Appointment(params);
  // save patient
  await newAppointment.save();

  return appointmentDetails(newAppointment);
}

async function updateCase(id, params) {
  const casse = await getCase(id);
  objIndex = casse.requiredDocuments.findIndex(
    (obj) => obj.documentTitle == params.documentTitle
  );
  if (objIndex === -1) {
    casse.requiredDocuments.push(params);
  } else {
    casse.requiredDocuments[objIndex].documentTitle = params.documentTitle;
    casse.requiredDocuments[objIndex].documentPath = params.documentPath;
    casse.requiredDocuments[objIndex].documentStatus = params.documentStatus;
  }
  // copy params to patient and save
  // Object.assign(casse, params);
  casse.updated = Date.now();
  await casse.save();

  return caseDetails(casse);
}

async function getCaseById(id) {
  const casse = await getCase(id);
  // const listg = await db.CaseType.findOne({ caseName: casse.caseType });
  const okay = await specificHospitalDetails(casse);
  // console.log("%j", okay);
  // okay.typeList = await db.CaseType.findOne({ caseName: casse.caseType });
  // okay.typeOptions = await db.CaseType.find({}).select("caseName");
  return okay;
}

// function generateRefreshToken(admin, ipAddress) {

//     // create a refresh token that expires in 7 days
//     return new db.AdminRefreshToken({
//         admin: admin.id,
//         token: randomTokenString(),
//         expires: new Date(Date.now() + 7*24*60*60*1000),
//         createdByIp: ipAddress
//     });
// }

async function update(id, params) {
  const patient = await getPatient(id);

  // validate (if email was changed)
  // if (params.email && patient.email !== params.email && await db.Patient.findOne({ email: params.email })) {
  //     throw 'Email "' + params.email + '" is already taken';
  // }

  // hash password if it was entered
  if (params.password) {
    params.passwordHash = hash(params.password);
  }

  // copy params to patient and save
  Object.assign(patient, params);
  patient.updated = Date.now();
  await patient.save();

  return basicDetails(patient);
}

async function _delete(id) {
  const patient = await getPatient(id);
  await patient.remove();
}

// helper functions

async function getPatient(id) {
  if (!db.isValidId(id)) throw "Patient not found";
  const patient = await db.Patient.findById(id);
  if (!patient) throw "Patient not found";
  return patient;
}

async function getAllCases(id) {
  const cases = await db.Case.find({ createdBy: id }).populate("assignedTo", [
    "id",
    "email",
    "firstName",
    "lastName",
    "city",
    "lawyerStatus",
  ]);
  return cases;
}

async function getCase(id) {
  if (!db.isValidId(id)) throw "Case not found";
  const casse = await db.Hospital.findById(id).populate(
    "requests.doctorProfile"
  );
  if (!casse) throw "Case not found";
  return casse;
}

async function getRefreshToken(token) {
  const refreshToken = await db.PatientRefreshToken.findOne({ token }).populate(
    "patient"
  );
  if (!refreshToken || !refreshToken.isActive) throw "Invalid token";
  return refreshToken;
}

function hash(password) {
  return bcrypt.hashSync(password, 10);
}

function generateJwtToken(patient) {
  // create a jwt token containing the patient id that expires in 15 minutes
  return jwt.sign({ sub: patient.id, id: patient.id }, secret, {
    expiresIn: "15m",
  });
}

function generateRefreshToken(patient, ipAddress) {
  // create a refresh token that expires in 7 days
  return new db.PatientRefreshToken({
    patient: patient.id,
    token: randomTokenString(),
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    createdByIp: ipAddress,
  });
}

function randomTokenString() {
  return crypto.randomBytes(40).toString("hex");
}

function randomTokenPin() {
  return Math.floor(Math.random() * (999999 - 100000 + 1) + 100000);
}

function basicDetails(patient) {
  const {
    id,
    firstName,
    lastName,
    patientStatus,
    email,
    phone,
    address,
    city,
    imageUrl,
    role,
    created,
    updated,
    isVerified,
  } = patient;
  return {
    id,
    firstName,
    lastName,
    patientStatus,
    email,
    phone,
    address,
    city,
    imageUrl,
    role,
    created,
    updated,
    isVerified,
  };
}

function linkedDoctorDetails(linkedDoctor) {
  const { id, firstName, lastName, email, title, doctorStatus, role, city, schedule } =
    linkedDoctor;
  return { id, firstName, lastName, email, title, doctorStatus, role, city, schedule };
}

async function specificHospitalDetails(hospital) {
  const { id, name, email, hospitalStatus, hospitalAddress, role, city } =
    hospital;
  if (hospital.requests) {
    const requests = [];
    await hospital.requests.map((x) => {
      if (x.linkStatus == "active") {
        // console.log("ooooooo", x);
        requests.push(linkedDoctorDetails(x.doctorProfile));
      }
    });
    return {
      id,
      name,
      email,
      hospitalStatus,
      hospitalAddress,
      role,
      city,
      requests,
    };
  } else {
    return {
      id,
      name,
      email,
      hospitalStatus,
      hospitalAddress,
      role,
      city,
    };
  }
}

function hospitalDetails(hospital) {
  const { id, name, email, hospitalStatus, hospitalAddress, role, city } =
    hospital;

  return {
    id,
    name,
    email,
    hospitalStatus,
    hospitalAddress,
    role,
    city,
  };
}

function documentType(requiredDocuments, caseType) {
  const newRequiredDocuments = [];
  if (caseType == "A") {
    const docs = ["cnic", "license", "tax"];
    docs.map((x) => {
      if (requiredDocuments.some((e) => e.documentTitle == x)) {
        const index = requiredDocuments.findIndex(
          (element) => element.documentTitle == x
        );
        newRequiredDocuments.push(requiredDocuments[index]);
      } else {
        newRequiredDocuments.push({
          documentTitle: x,
          documentStatus: "required",
          documentPath: "",
        });
      }
    });
    return newRequiredDocuments;
  } else if (caseType == "B") {
    const docs = ["cnic", "tax"];
    docs.map((x) => {
      if (requiredDocuments.some((e) => e.documentTitle == x)) {
        const index = requiredDocuments.findIndex(
          (element) => element.documentTitle == x
        );
        newRequiredDocuments.push(requiredDocuments[index]);
      } else {
        newRequiredDocuments.push({
          documentTitle: x,
          documentStatus: "required",
          documentPath: "",
        });
      }
    });
    return newRequiredDocuments;
  } else if (caseType == "C") {
    const docs = ["license", "tax"];
    docs.map((x) => {
      if (requiredDocuments.some((e) => e.documentTitle == x)) {
        const index = requiredDocuments.findIndex(
          (element) => element.documentTitle == x
        );
        newRequiredDocuments.push(requiredDocuments[index]);
      } else {
        newRequiredDocuments.push({
          documentTitle: x,
          documentStatus: "required",
          documentPath: "",
        });
      }
    });
    return newRequiredDocuments;
  } else if (caseType == "D") {
    const docs = ["license", "book"];
    docs.map((x) => {
      if (requiredDocuments.some((e) => e.documentTitle == x)) {
        const index = requiredDocuments.findIndex(
          (element) => element.documentTitle == x
        );
        newRequiredDocuments.push(requiredDocuments[index]);
      } else {
        newRequiredDocuments.push({
          documentTitle: x,
          documentStatus: "required",
          documentPath: "",
        });
      }
    });
    return newRequiredDocuments;
  }
  return requiredDocuments;
}

function findRequired(mondayId) {
  let query = `{boards(ids:2192166962) { items(ids:${mondayId}){ column_values{title text } } } }`;
  return fetch("https://api.monday.com/v2", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
      Authorization: mondToken,
    },
    body: JSON.stringify({
      query: query,
    }),
  })
    .then((res) => res.json())
    .then((res) => {
      return res.data.boards[0].items[0].column_values;
    });
}

async function caseDetails(casse) {
  let statusMessages;
  let {
    id,
    caseSubject,
    caseType,
    caseStatus,
    caseMessage,
    assignedTo,
    createdBy,
    created,
    updated,
    mondayAcc,
    requiredDocuments,
    document01,
    document02,
    document03,
  } = casse;
  // requiredDocuments = documentType(requiredDocuments, caseType);
  if (mondayAcc.mondayId !== "") {
    await findRequired(mondayAcc.mondayId).then((res) => {
      statusMessages = res;
    });
  }
  return {
    id,
    caseSubject,
    caseType,
    caseStatus,
    caseMessage,
    assignedTo,
    createdBy,
    created,
    updated,
    mondayAcc,
    requiredDocuments,
    statusMessages,
    document01,
    document02,
    document03,
  };
}

async function appointmentDetails(casse) {
  let {
    id,
    time, patientId, doctorId, appointmentStatus, appointmentView, updated
  } = casse;
  // requiredDocuments = documentType(requiredDocuments, caseType);

  return {
    id,
    time, patientId, doctorId, appointmentStatus, appointmentView, updated
  };
}

async function sendVerificationEmail(patient, origin) {
  let message = `<p>Validation PIN:</p>
                   <p><code>${patient.verificationToken}</code></p>`;

  await sendEmail({
    to: patient.email,
    subject: "Sign-up Verification API - Verify Email",
    html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`,
  });
}

async function sendAlreadyRegisteredEmail(email, origin) {
  let message;
  if (origin) {
    message = `<p>If you don't know your password please visit the <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
  } else {
    message = `<p>If you don't know your password you can reset it via the <code>/account/forgot-password</code> api route.</p>`;
  }

  await sendEmail({
    to: email,
    subject: "Sign-up Verification API - Email Already Registered",
    html: `<h4>Email Already Registered</h4>
               <p>Your email <strong>${email}</strong> is already registered.</p>
               ${message}`,
  });
}

async function sendPasswordResetEmail(patient, origin) {
  let message;
  if (origin) {
    const resetUrl = `${origin}/account/reset-password?token=${patient.resetToken.token}`;
    message = `<p>Password Reset PIN, Valid for 1 hour.:</p>
        <p><code>${patient.resetToken.token}</code></p>`;
  } else {
    message = `<p>Password Reset PIN, Valid for 1 hour.:</p>
                   <p><code>${patient.resetToken.token}</code></p>`;
  }

  await sendEmail({
    to: patient.email,
    subject: "Sign-up Verification API - Reset Password",
    html: `<h4>Reset Password Email</h4>
               ${message}`,
  });
}
