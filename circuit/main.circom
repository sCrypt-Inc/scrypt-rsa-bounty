pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";

include "ecdsa/ecdsa.circom";
include "ecdsa/secp256k1.circom";
include "poseidon/poseidon.circom";
include "util.circom";

// Circuit of private information bounty for prime factors (p, q) of an RSA modulus n = p*q.
// -------
// chunksModulus --> Number of 64-bit chunks to represent the RSA modulus. I.e. 32 for a 2048-bit modulus.
// chunksFactor  --> Number of 64-bit chunks to represent factors p or q. I.e. 16 for a 2048-bit modulus. // TODO
// lCyphertext   --> Length of encrypted secret (chunksFactor * 2 + 2). See poseidon encryption implementation regarding the +2
template Main(chunksModulus, chunksFactor, lCyphertext) {

    // Private inputs:
    signal input p[chunksFactor];            // p, q such that p * q == n
    signal input q[chunksFactor];
    signal input db[4];                      // Seller (Bob) private key.
    signal input Qs[2][4];                   // Shared (symmetric) key. Used to encrypt w.
    
    // "Public" inputs that are still passed as private to reduce verifier size on chain:
    signal input n[chunksModulus];           // RSA modulus n = p*q;
    signal input Qa[2][4];                   // Buyer (Alice) public key.
    signal input Qb[2][4];                   // Seller (Bob) public key.
    signal input nonce;                      // Needed to encrypt/decrypt xy.
    signal input ew[lCyphertext];            // Encrypted solution to puzzle.

    // Public inputs:
    signal input Hpub[2];            // Hash of inputs that are supposed to be public.
                                     // As we use SHA256 in this example, we need two field elements
                                     // to acommodate all possible hash values.

    
    //// Assert that public inputs hash to Hpub. ///////////////////////////////////
    // We first turn each inputs into an array of bits and then concatinate 
    // them together for the hash preimage. We use SHA256.
    component nBitsByPart = Num2BitsMultipleReverse(chunksModulus, 256); // TODO: these are 64 bit chunks and can be made smaller
    for (var i = 0; i < chunksModulus; i++) {
        nBitsByPart.in[i] <== n[i];
    }

    component ewBitsByPart = Num2BitsMultipleReverse(lCyphertext, 256);
    for (var i = 0; i < lCyphertext; i++) {
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

    component hashCheck = Sha256(chunksModulus * 256 + 512 * 2 + 256 + lCyphertext * 256);

    for (var i = 0; i < 512; i++) {
        hashCheck.in[i] <== QaBits.out[i];
        hashCheck.in[i + 512] <== QbBits.out[i];
    }

    for (var i = 0; i < 256; i++) {
        hashCheck.in[i + 1024] <== nonceBits.out[255 - i];
    }

    for (var i = 0; i < lCyphertext; i++) {
        for (var j = 0; j < 256; j++) {
            hashCheck.in[i * 256 + j + 1280] <== ewBitsByPart.out[i][j];
        }
    }

    for (var i = 0; i < chunksModulus; i++) {
        for (var j = 0; j < 256; j++) {
            hashCheck.in[i * 256 + j + 9984] <== nBitsByPart.out[i][j];
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
    // Check none of p or q are equal to 1
    component pe1 = BigIsEqual(chunksFactor);
    for (var i = 0; i < chunksFactor; i++) {
        pe1.in[0][i] <== p[i];
    }
    pe1.in[1][0] <== 1;
    for (var i = 1; i < chunksFactor; i++) {
        pe1.in[1][i] <== 0;
    }
    component isz0 = IsZero();
    isz0.in <== pe1.out;
    isz0.out === 1;

    component qe1 = BigIsEqual(chunksFactor);
    for (var i = 0; i < chunksFactor; i++) {
        qe1.in[0][i] <== q[i];
    }
    qe1.in[1][0] <== 1;
    for (var i = 1; i < chunksFactor; i++) {
        qe1.in[1][i] <== 0;
    }
    component isz1 = IsZero();
    isz1.in <== qe1.out;
    isz1.out === 1;

    // Check if n == p * q.
    component pq = BigMult(64, chunksFactor);
    for (var i = 0; i < chunksFactor; i++) {
        pq.a[i] <== p[i];
        pq.b[i] <== q[i];
    }

    for (var i = 0; i < chunksModulus; i++) {
        n[i] === pq.out[i];
    }

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
    component posEnc = PoseidonEncryptCheck(chunksFactor * 2);

    for (var i = 0; i < lCyphertext; i++) {
        posEnc.ciphertext[i] <== ew[i];
    }

    for (var i = 0; i < chunksFactor; i++) {
        posEnc.message[i] <== p[i];
        posEnc.message[chunksFactor + i] <== q[i];
    }
    
    component sharedKey = FromatSharedKey();
    sharedKey.pointX[0] <== Qs[0][0];
    sharedKey.pointX[1] <== Qs[0][1];
    sharedKey.pointX[2] <== Qs[0][2];
    sharedKey.pointX[3] <== Qs[0][3];

    posEnc.nonce <== nonce;
    posEnc.key[0] <== sharedKey.ks[0];
    posEnc.key[1] <== sharedKey.ks[1];
    posEnc.out === 1;
    
}