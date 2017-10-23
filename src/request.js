const levee = require('levee');
const request = require('request');

const circuit = levee.createBreaker(request, {
    maxFailures: 5,
    timeout: 60000,
    resetTimeout: 30000,
});

const circuitRequest = (requestOptions) => {
    return new Promise((resolve, reject) => {
        circuit.run(requestOptions, (err, response, body) => {
            if (err) {
                return reject(err);
            }

            if (response.statusCode > 100 && response.statusCode < 400) {
                return resolve(body);
            }

            reject(body);
        });
    });
};

module.exports = circuitRequest;
