let base64 = require('base-64');
const fetch = require('node-fetch');
const dotenv = require('dotenv');
const { response } = require('express');
dotenv.config();


module.exports = {
    _getInfo,
    _getPred
}

async function _getInfo() {
    const username = process.env.CHAIN_USERNAME;
    const password = process.env.CHAIN_PASSWORD
    let options = {
        method: "getinfo"
    }
    let response = await fetch(process.env.CHAIN_URI, {
        method: 'POST',
        headers: {
            'Authorization': 'Basic ' + base64.encode(username + ":" + password)
        },
        body: JSON.stringify(
            options
        )
    });
    return response.text();
}

async function _getPred(data) {
    let response = await fetch(process.env.MODEL_URI, {
        method: 'POST',
        body: JSON.stringify(
            data
        )
    });
    return response.text();
}


