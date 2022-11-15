pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";

include "ecdsa/ecdsa.circom";
include "ecdsa/secp256k1.circom";
include "poseidon/poseidon.circom";
include "util.circom";

// Circuit of private information bounty for prime factors (p, q) of an RSA modulus n = p*q.
template Main() {

    // Private inputs:
    signal input w[2];              // p, q such that p * q == n
    signal input db[4];             // Seller (Bob) private key.
    signal input Qs[2][4];          // Shared (symmetric) key. Used to encrypt w.
    
    // "Public" inputs that are still passed as private to reduce verifier size on chain:
    signal input n;                 // RSA modulus n = p*q;
    signal input Qa[2][4];          // Buyer (Alice) public key.
    signal input Qb[2][4];          // Seller (Bob) public key.
    signal input nonce;             // Needed to encrypt/decrypt xy.
    signal input ew[4];             // Encrypted solution to puzzle.

    // Public inputs:
    signal input Hpub[2];            // Hash of inputs that are supposed to be public.
                                     // As we use SHA256 in this example, we need two field elements
                                     // to acommodate all possible hash values.

    
    //// Assert that public inputs hash to Hpub. ///////////////////////////////////
    // We first turn each inputs into an array of bits and then concatinate 
    // them together for the hash preimage. We use SHA256.
    component ewBitsByPart = Num2BitsMultipleReverse(4, 256);
    for (var i = 0; i < 4; i++) {
        ewBitsByPart.in[i] <== ew[i];
    }
    component QaBits = Point2Bits();
    component QbBits = Point2Bits();
    for (var i = 0; i < 4; i++) {
        QaBits.in[0][i] <== Qa[0][i];
        QaBits.in[1][i] <== Qa[1][i];
        QbBits.in[0][i] <== Qb[0][i];
        QbBits.in[1][i] <== Qb[1][i];
    }
    
    component nonceBits = Num2Bits(256);
    nonceBits.in <== nonce;

    component hashCheck = Sha256(512 * 2 + 256 + 4 * 256);

    for (var i = 0; i < 512; i++) {
        hashCheck.in[i] <== QaBits.out[i];
        hashCheck.in[i + 512] <== QbBits.out[i];
    }

    for (var i = 0; i < 256; i++) {
        hashCheck.in[i + 1024] <== nonceBits.out[255 - i];
    }

    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 256; j++) {
            hashCheck.in[i * 256 + j + 1280] <== ewBitsByPart.out[i][j];
        }
    }

    component Hpub0 = BitArr2Num(128);
    component Hpub1 = BitArr2Num(128);
    for (var i = 0; i < 128; i++) {
        Hpub0.in[i] <== hashCheck.out[i];
        Hpub1.in[i] <== hashCheck.out[i + 128];
    }
    Hpub[0] === Hpub0.out;
    Hpub[1] === Hpub1.out;

    //// Assert w is a valid solution. //////////////////////////////////////////////
    n === w[0] * w[1];

    //// Assert that (db * Qa) = Qs ////////////////////////////////////////////////
    // This will ensure that Bob actually derived Qs using Alices public key Qa.
    // This uses Circom code to emulate operations on secp256k1 by 0xPARC:
    // https://github.com/0xPARC/circom-ecdsa
    component privToPub0 = Secp256k1ScalarMult(64, 4);
    for (var i = 0; i < 4; i++) {
        privToPub0.scalar[i] <== db[i];
    }
    for (var i = 0; i < 4; i++) {
        privToPub0.point[0][i] <== Qa[0][i];
        privToPub0.point[1][i] <== Qa[1][i];
    }

    signal Qs_x_diff[4];
    signal Qs_y_diff[4];
    for (var i = 0; i < 4; i++) {
        Qs_x_diff[i] <-- privToPub0.out[0][i] - Qs[0][i];
        Qs_x_diff[i] === 0;
        Qs_y_diff[i] <-- privToPub0.out[1][i] - Qs[1][i];
        Qs_y_diff[i] === 0;
    }

    //// Assert that (db * G) = Qb /////////////////////////////////////////////////
    // This makes sure that Qb is really the public key corresponding to db.
    component privToPub1 = ECDSAPrivToPub(64, 4);
    for (var i = 0; i < 4; i++) {
        privToPub1.privkey[i] <== db[i];
    }

    signal Qb_x_diff[4];
    signal Qb_y_diff[4];
    for (var i = 0; i < 4; i++) {
        Qb_x_diff[i] <-- privToPub1.pubkey[0][i] - Qb[0][i];
        Qb_x_diff[i] === 0;
        Qb_y_diff[i] <-- privToPub1.pubkey[1][i] - Qb[1][i];
        Qb_y_diff[i] === 0;
    }

    //// Assert that encrypting w with Qs produces ew. /////////////////////////////
    // To achieve that, we use Poseidon Ecryption. Templates are sourced from here:
    // https://github.com/weijiekoh/poseidon-encryption-circom
    // We split the x-coordinate of Qs into 4 field elements and use that as the 
    // encryption key. The encryption also uses a nonce which is passed as a public input.
    // The nonce can just be a timestamp for example.
    component p = PoseidonEncryptCheck(2);

    for (var i = 0; i < 4; i++) {
        p.ciphertext[i] <== ew[i];
    }

    for (var i = 0; i < 2; i++) {
        p.message[i] <== w[i];
    }
    
    component sharedKey = FromatSharedKey();
    sharedKey.pointX[0] <== Qs[0][0];
    sharedKey.pointX[1] <== Qs[0][1];
    sharedKey.pointX[2] <== Qs[0][2];
    sharedKey.pointX[3] <== Qs[0][3];

    p.nonce <== nonce;
    p.key[0] <== sharedKey.ks[0];
    p.key[1] <== sharedKey.ks[1];
    //p.out === 1;
    
}