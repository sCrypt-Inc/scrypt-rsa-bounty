import { expect } from 'chai';

import path = require("path");
const fs = require("fs");

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from './util/poseidonEncryption';


import { sha256 } from "scryptlib";

import { bigIntToArray } from './util/misc';

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;



describe("MainCircuit", function () {
    this.timeout(1000 * 1000 * 10);

    let da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
    let Qa: Point = Point.fromPrivateKey(da);
    let QaxArray = bigIntToArray(64, 4, Qa.x);
    let QayArray = bigIntToArray(64, 4, Qa.y);

    let p: bigint = 84102226189931597204228074020861136329889927593666544679790818418208050232689529735088785671967555126288131210906309673238385952888184646056701546267152983157209204178832636744126636676765506035710343020385405332519258369909033933883276849025592411318178524227006970911149528928068344969907921225222253552759n;
    let q: bigint = 69227124116797173792607322097623651900186824540546740345955227424547330221880094641332718074911771220677020023646982676844502920924653525076956524065499369561259749151984512521544089172137726149696268189532069007446227350457277994250148911361041938621241351126892097452001343025320798183836404152872960236563n;

    let n: bigint = p * q;
    
    let pArray = bigIntToArray(64, 16, p);
    let qArray = bigIntToArray(64, 16, q);
    let nArray = bigIntToArray(64, 32, n);

    let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
    let Qb: Point = Point.fromPrivateKey(db);

    let Qs: Point = Qb.multiply(da);

    let dbArray = bigIntToArray(64, 4, db);
    let QbxArray = bigIntToArray(64, 4, Qb.x);
    let QbyArray = bigIntToArray(64, 4, Qb.y);
    let QsxArray = bigIntToArray(64, 4, Qs.x);
    let QsyArray = bigIntToArray(64, 4, Qs.y);

    let nonce = BigInt(1234);
    let ew = poseidonEncrypt(pArray.concat(qArray), formatSharedKey(QsxArray), nonce);
    
    let QaHex = Qa.toHex(false).slice(2);  // Slice away "04" at the beggining from uncompressed encoding.
    let QbHex = Qb.toHex(false).slice(2);
    
    let nonceHex = nonce.toString(16);
    nonceHex =  "0".repeat(64 - nonceHex.length) + nonceHex;
    
    let ewHex = '';
    for (var i = 0; i < ew.length; i++) {
        let partStr = ew[i].toString(16);
        ewHex += "0".repeat(64 - partStr.length) + partStr;
    }
    let Hpub = sha256(QaHex + QbHex + nonceHex + ewHex);
    let Hpub0 = BigInt('0x' + Hpub.substring(0, 32));
    let Hpub1 = BigInt('0x' + Hpub.substring(32, 64));

    let circuit: any;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_main_allpublic.circom"));
    });

    it('Testing main circuit with correct inputs',
        async function () {
            let witness = await circuit.calculateWitness(
                {
                    "p": pArray,
                    "q": qArray,
                    "db": dbArray,
                    "Qs": [QsxArray, QsyArray],
                    "n": nArray,
                    "Qa": [QaxArray, QayArray],
                    "Qb": [QbxArray, QbyArray],
                    "nonce": nonce,
                    "ew": ew,
                    "Hpub": [Hpub0, Hpub1]
                }
            );
            await circuit.checkConstraints(witness);
        }
    );

    it('Testing main circuit with wrong solution',
        async function () {
            let pWrong: bigint = 124322n;
            let pWrongArray = bigIntToArray(64, 16, pWrong);

            let ewWrong = poseidonEncrypt(pWrongArray.concat(qArray), formatSharedKey(QsxArray), nonce);

            let witnessCalcSucceeded = true;
            try {
                // Witness generation should fail.
                let witness = await circuit.calculateWitness(
                    {
                        "p": pWrongArray,
                        "q": qArray,
                        "db": dbArray,
                        "Qs": [QsxArray, QsyArray],
                        "n": nArray,
                        "Qa": [QaxArray, QayArray],
                        "Qb": [QbxArray, QbyArray],
                        "nonce": nonce,
                        "ew": ewWrong,
                        "Hpub": [Hpub0, Hpub1]
                    }
                );
            } catch (e) {
                witnessCalcSucceeded = false;
            }
            expect(witnessCalcSucceeded).to.equal(false);
        }
    );

    it('Testing main circuit with Qs != db * Qa',
        async function () {
        
            let randPriv: bigint = 37192864923864928634293846263598265893468791234710n;
            let QsWrong = Point.fromPrivateKey(randPriv);

            let QsWrongxArray = bigIntToArray(64, 4, QsWrong.x);
            let QsWrongyArray = bigIntToArray(64, 4, QsWrong.y);

            let witnessCalcSucceeded = true;
            try {
                // Witness generation should fail.
                let witness = await circuit.calculateWitness(
                    {
                        "p": pArray,
                        "q": qArray,
                        "db": dbArray,
                        "Qs": [QsWrongxArray, QsWrongyArray],
                        "n": nArray,
                        "Qa": [QaxArray, QayArray],
                        "Qb": [QbxArray, QbyArray],
                        "nonce": nonce,
                        "ew": ew,
                        "Hpub": [Hpub0, Hpub1]
                    }
                );
            } catch (e) {
                witnessCalcSucceeded = false;
            }
            expect(witnessCalcSucceeded).to.equal(false);
        }
    );

    it('Testing main circuit with Qb != db * G',
        async function () {
        
            let randPriv: bigint = 123781927462385736487953469857609124837219078043573n;
            let QbWrong = Point.fromPrivateKey(randPriv);

            let QbWrongxArray = bigIntToArray(64, 4, QbWrong.x);
            let QbWrongyArray = bigIntToArray(64, 4, QbWrong.y);

            let witnessCalcSucceeded = true;
            try {
                // Witness generation should fail.
                let witness = await circuit.calculateWitness(
                    {
                        "p": pArray,
                        "q": qArray,
                        "db": dbArray,
                        "Qs": [QsxArray, QsyArray],
                        "n": nArray,
                        "Qa": [QaxArray, QayArray],
                        "Qb": [QbWrongxArray, QbWrongyArray],
                        "nonce": nonce,
                        "ew": ew,
                        "Hpub": [Hpub0, Hpub1]
                    }
                );
            } catch (e) {
                witnessCalcSucceeded = false;
            }
            expect(witnessCalcSucceeded).to.equal(false);
        }
    );

});
