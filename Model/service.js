let base64 = require("base-64");
const fetch = require("node-fetch");
const { response } = require("express");
const { chainUri, chainPassword, chainUsername } = require("../config");

module.exports = {
  _getInfo,
  _getPred,
};

async function _getInfo() {
  let options = {
    method: "getinfo",
  };
  let response = await fetch(chainUri, {
    method: "POST",
    headers: {
      Authorization:
        "Basic " + base64.encode(chainUsername + ":" + chainPassword),
    },
    body: JSON.stringify(options),
  });
  return response.text();
}

async function _getPred(data) {
  let response = await fetch(process.env.MODEL_URI, {
    method: "POST",
    body: JSON.stringify(data),
  });
  return response.text();
}
