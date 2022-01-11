const { response } = require('express');
const express = require('express');
const router = express.Router();

const service = require('./service');

router.post('/getpred', _getPred);
router.post('/getinfo', _getInfo);

module.exports = router;


function _getInfo(req, res, next) {
    service._getInfo()
        .then(data => {
            res.send(data);
        })
        .catch(next)
}

function _getPred(req, res, next) {
    service._getPred(req.body)
        .then(data => {
            res.send({result:data});
        })
        .catch(next)
}