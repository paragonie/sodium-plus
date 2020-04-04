const { expect } = require('chai');
module.exports = async function expectError(promised, message) {
    let thrown = false;
    try {
        await promised;
    } catch (e) {
        thrown = true;
        expect(message).to.be.equal(e.message);
    }
    if (!thrown) {
        throw new Error('Function did not throw');
    }
};
