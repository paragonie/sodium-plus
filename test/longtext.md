<!-- From a blog post -- https://paragonie.com/blog/2019/10/improving-cryptography-javascript-ecosystem -->

It's been more than eight years since [Javascript Cryptography Considered Harmful](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/august/javascript-cryptography-considered-harmful) was published.

It's just as true today as it was eight years ago that JavaScript cryptography in a web browser is dangerous. **But the *ecosystem* itself has changed immensely in this time.**

## JavaScript Cryptography, Considered

Between the continued rise in popularity of JavaScript frameworks (e.g. React) and the prevalence of cross-platform development tools (Cordova, Electron), it's now possible to write JavaScript code once and deploy it on a web server, in a webpage, in a browser extension, in a native mobile app, and in desktop software... with no changes to your JavaScript code.

Despite eight years of transformative change to the programming landscape, the JavaScript ecosystem has been severely neglected by the security industry, especially with regards to usable cryptography.

<!--
### Putting Skin in the Game

Anyone who's already familiar with our work knows this already, but we find the security industry's neglect of programming language ecosystems simply *unacceptable*.

Instead of unhelpful remarks like "Want your code to be secure? Stop writing it in [languages the security industry dislike]", the security industry's responsibility should be to make the languages and tools developers want to use secure.

This is as true for how Node.js developers are treated by many security experts today as it was for how PHP developers were treated five years ago.

Unlike most security companies, we're actually putting in the time and work to improve matters. We encourage our colleagues, and challenge our competitors, to step up and do the same (or, at the very least, cease with the gatekeeping remarks).
-->

## What PIE Has Already Done for JavaScript Cryptography

### Sodium-Plus - A Positive Experience for JS Cryptography

This month we released [Sodium-Plus](https://github.com/paragonie/sodium-plus), a pluggable, cross-platform, type-safe interface for libsodium to make it easier to write safe and secure JavaScript cryptography code. Our initial announcement was [posted on dev.to](https://dev.to/paragonie/sodium-plus-a-positive-cryptography-experience-for-javascript-developers-2p08).

To be clear: This isn't a new libsodium binding. What sodium-plus does is wrap one of the existing bindings (e.g. [sodium-native](https://github.com/paragonie/sodium-plus)) and—regardless of how unpleasant the low-level binding's API is to work with—lets you interact with it using a sane and simple asynchronous API.

Instead of writing code like this:

<pre><code class="javascript">const sodium = require('sodium-native');

// Key generation
let aliceSecret = Buffer.alloc(32);
let alicePublic = Buffer.alloc(32);
let bobSecret = Buffer.alloc(32);
let bobPublic = Buffer.alloc(32);
sodium.crypto_box_keypair(alicePublic, aliceSecret);
sodium.crypto_box_keypair(bobPublic, bobSecret);

// Nonce
let nonce = Buffer.alloc(24);
sodium.randombytes_buf(nonce);

// Plaintext
let message = 'A string I want to encrypt.';
let plaintext = Buffer.from(message);

// Encrypt
let ciphertext = Buffer.alloc(plaintext.length + 16);
sodium.crypto_box_easy(ciphertext, plaintext, nonce, bobPublic, aliceSecret);
console.log(ciphertext.toString('hex'));

// Decrypt
let decrypted = Buffer.alloc(ciphertext.length - 16);
sodium.crypto_box_open_easy(decrypted, ciphertext, nonce, alicePublic, bobSecret);
console.log(decrypted.toString());
</code></pre>

...you can just write this:

<pre><code class="javascript">const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let aliceKeypair = await sodium.crypto_box_keypair();
        let aliceSecret = await sodium.crypto_box_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_box_publickey(aliceKeypair);
    let bobKeypair = await sodium.crypto_box_keypair();
        let bobSecret = await sodium.crypto_box_secretkey(bobKeypair);
        let bobPublic = await sodium.crypto_box_publickey(bobKeypair);
    
    let nonce = await sodium.randombytes_buf(24);
    let plaintext = 'Your message goes here';
    let ciphertext = await sodium.crypto_box(plaintext, nonce, aliceSecret, bobPublic);    
    console.log(ciphertext.toString('hex'));

    let decrypted = await sodium.crypto_box_open(ciphertext, nonce, bobSecret, alicePublic);
    console.log(decrypted.toString());
})();
</code></pre>

The second snippet works in browsers, browser extensions, mobile apps, desktop apps, and webservers, without requiring a C compiler be integrated into your JavaScript toolkit.

By default, Sodium-Plus uses [libsodium-wrappers](https://github.com/jedisct1/libsodium.js). However, if sodium-native is installed, it will opportunistically use that first, since sodium-native offers much better performance.

One of the many features included in Sodium-Plus is type-safety with cryptography keys. An `Ed25519SecretKey` cannot be used by `crypto_box()`, only by `crypto_sign()`. This prevents a whole host of usage mistakes that passing around bare `Buffer` objects cannot prevent.

Check out [the Sodium-Plus documentation](https://github.com/paragonie/sodium-plus/tree/master/docs) for more information.

### Certainty.js: CACert Management for JavaScript Projects

We originally created [Certainty](https://paragonie.com/blog/2017/10/certainty-automated-cacert-pem-management-for-php-software) to solve the problem of "developers disabling SSL/TLS verification", which was in many cases actually a symptom of the "unreliable/outdated CACert bundle" problem.

Until recently, there was no congruent means for auto-updating your CACert bundles for Node.js developers. So we decided to write [certainty.js](https://github.com/paragonie/certainty-js).

<pre><code class="javascript">const {Certainty} = require('certainty-js');
const http = require('request-promise-native');

(async function () {
    let options = {
        'ca': await Certainty.getLatestCABundle('/path/to/directory'),
        'uri': 'https://php-chronicle.pie-hosted.com/chronicle/lasthash',
        'minVersion': 'TLSv1.2',
        'strictSSL': true,
        'timeout': 30000
    };

    // Send request...
    console.log(await http.get(options));
})();</code></pre>

The next releases of Certainty.js will include the LocalCACertBuilder features from the PHP version, as well as a refactor to use `Sodium-Plus`.

### CipherSweet.js

Scenario: You need to encrypt some of your database fields, but you still need to use those fields in SELECT queries somehow. Is there a secure way to achieve this result without having to invoke a lot of new and experimental cryptography primitives?

It turns out: Yes, you can. Our proposed implementation is called [CipherSweet](https://paragonie.com/blog/2019/01/ciphersweet-searchable-encryption-doesn-t-have-be-bitter).

CipherSweet has already been ported from PHP to Node.js, with other languages coming soon.

You can find [CipherSweet-js](https://github.com/paragonie/ciphersweet-js) on Github. The documentation is available [on our website](https://ciphersweet.paragonie.com/node.js).

## Our Work Continues

Like many other programming languages, JavaScript has its own needs and unique challenges. We 
remain committed to improving the security and usability of the languages, frameworks, and tools developers want to use, and strive towards a more private and secure Internet for everyone.

If your company relies on PHP or JavaScript code and needs expert assistance with solving cryptography problems in your application, [reach out to us](https://paragonie.com/contact). We [write code](https://paragonie.com/service/app-dev), [audit code](https://paragonie.com/service/code-review), and [offer consultation for security designs](https://paragonie.com/service/technology-consulting).
