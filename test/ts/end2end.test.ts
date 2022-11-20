import { expect } from 'chai';
import path = require("path");
const fs = require("fs");
const crypto = require("crypto");
import { execSync } from 'child_process';


import {
    buildContractClass, buildTypeClasses,
    hash160, Ripemd160, bsv, getPreimage, sha256,
    buildPublicKeyHashScript, signTx, findCompiler, compile, Sha256
} from "scryptlib";
const snarkjs = require('snarkjs');

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey, poseidonDecrypt } from './util/poseidonEncryption';

import { bigIntToArray, bigIntToHexStrFixedLen, vKeyToSCryptType, proofToSCryptType } from './util/misc';


// This file test the full end-to-end process of an information bounty as described by the patent.

const da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
const Qa: Point = Point.fromPrivateKey(da);
const QaxArray = bigIntToArray(64, 4, Qa.x);
const QayArray = bigIntToArray(64, 4, Qa.y);
const rewardSats = 10000;
const contractExpireBlock = 761406;

const p: bigint = 84102226189931597204228074020861136329889927593666544679790818418208050232689529735088785671967555126288131210906309673238385952888184646056701546267152983157209204178832636744126636676765506035710343020385405332519258369909033933883276849025592411318178524227006970911149528928068344969907921225222253552759n;
const q: bigint = 69227124116797173792607322097623651900186824540546740345955227424547330221880094641332718074911771220677020023646982676844502920924653525076956524065499369561259749151984512521544089172137726149696268189532069007446227350457277994250148911361041938621241351126892097452001343025320798183836404152872960236563n;

const n: bigint = p * q;

describe("End2End", function () {
    this.timeout(1000 * 1000 * 10);

    let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
    let Qb: Point = Point.fromPrivateKey(db);

    let Qs: Point = Qb.multiply(da);
    
    let pArray = bigIntToArray(64, 16, p);
    let qArray = bigIntToArray(64, 16, q);
    let nArray = bigIntToArray(64, 32, n);

    let dbArray = bigIntToArray(64, 4, db);
    let QbxArray = bigIntToArray(64, 4, Qb.x);
    let QbyArray = bigIntToArray(64, 4, Qb.y);
    let QsxArray = bigIntToArray(64, 4, Qs.x);
    let QsyArray = bigIntToArray(64, 4, Qs.y);

    let nonce = BigInt(1234); // TODO
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

    let nHex = '';
    for (var i = 0; i < nArray.length; i++) {
        let partStr = nArray[i].toString(16);
        nHex += "0".repeat(64 - partStr.length) + partStr;
    }

    let pubInputsHex = QaHex + QbHex + nonceHex + ewHex + nHex;
    let Hpub = sha256(pubInputsHex);
    let Hpub0 = BigInt('0x' + Hpub.substring(0, 32));
    let Hpub1 = BigInt('0x' + Hpub.substring(32, 64));

    let infoBounty: any;
    let vKey: any;
    let ContractTypes: any;

    let witness: any;
    let proof: any;
    let publicSignals: any;

    before(async function () {
        // TODO: Don't write these files to the root dir. Cd into some tmp dir or something.

        // Compile circuit.
        let circuitPath = path.join(__dirname, 'circuits', 'test_main.circom');
        let output = execSync(`circom ${circuitPath} --r1cs --wasm --sym`).toString();
        console.log(output);

        output = execSync(`snarkjs groth16 setup test_main.r1cs pot22_final.ptau circuit_0000.zkey`).toString();
        console.log(output);

        // IMPORTANT: When using Groth16 in production you need a phase 2 contribution here:
        // https://github.com/iden3/snarkjs#groth16

        output = execSync(`snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json`).toString();
        console.log(output);

        vKey = JSON.parse(fs.readFileSync("verification_key.json"));

        // Generate proof.
        witness = {
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
        };

        fs.writeFileSync("input.json", JSON.stringify(witness), function (err: any) {
            if (err) {
                console.log(err);
            }
        });

        output = execSync(`node test_main_js/generate_witness.js test_main_js/test_main.wasm input.json witness.wtns`).toString();
        console.log(output);
        output = execSync(`snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json`).toString();
        console.log(output);
        proof = JSON.parse(fs.readFileSync("proof.json").toString());
        publicSignals = JSON.parse(fs.readFileSync("public.json").toString());

        // Compile sCrypt conract.
        let filePath = path.join(__dirname, '..', '..', 'contracts', 'bounty.scrypt');
        let out = path.join(__dirname, '..', '..', 'out-scrypt');
        if (!fs.existsSync(out)) {
            fs.mkdirSync(out);
        }

        //let result = compileContract(filePath, { out: out, desc: true });
        let result = compile(
            { path: filePath },
            {
                desc: true,
                asm: false,
                ast: true,
                debug: true,
                hex: true,
                stdout: false,
                outputDir: out,
                outputToFiles: false,
                cmdPrefix: findCompiler(),
                timeout: 7200000
            }
        );

        if (result.errors.length > 0) {
            console.log(`Compile contract ${filePath} failed: `, result.errors);
            throw result.errors;
        }
        const RSABounty = buildContractClass(result);

        //const desc = JSON.parse(fs.readFileSync(path.join(out, "bounty_desc.json")).toString());
        //const InformationBounty = buildContractClass(desc);

        ContractTypes = buildTypeClasses(RSABounty);

        infoBounty = new RSABounty(
            new ContractTypes.ECPoint({ x: QaxArray, y: QayArray }),
            n,
            vKeyToSCryptType(vKey, ContractTypes),
            rewardSats,
            contractExpireBlock
        );

    });

    it('Testing proof verification with snarkjs',
        async function () {
            // Verify proof in js.
            let res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
            expect(res).to.be.true;
        }
    );

    it('Testing proof verification with sCrypt',
        async function () {
            // Verify proof in sCrypt / Bitcoin script.

            let newLockingScript = buildPublicKeyHashScript(new Ripemd160(hash160(
                "04" + Qb.x.toString(16) + Qb.y.toString(16)
            )));

            let inputSatoshis = rewardSats;
            let utxo = {
                txId: crypto.randomBytes(32).toString('hex'),
                outputIndex: 0,
                script: infoBounty.lockingScript,
                satoshis: inputSatoshis
            };
            let tx = new bsv.Transaction().from(utxo);

            tx.addOutput(new bsv.Transaction.Output({
                script: newLockingScript,
                satoshis: rewardSats
            }))

            let dataOutScript = "006a" + pubInputsHex;

            tx.addOutput(new bsv.Transaction.Output({
                script: dataOutScript,
                satoshis: 0
            }))

            let preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)

            let context = { tx, inputIndex: 0, inputSatoshis };
            const result = infoBounty.unlock(
                new ContractTypes.ECPoint({ x: QbxArray, y: QbyArray }),
                ew,
                new Sha256(Hpub),
                nonce,
                proofToSCryptType(proof, ContractTypes),
                preimage
            ).verify(context);
            expect(result.success, result.error).to.be.true;
        }
    );

    it('Testing parsing and decrypting solution',
        async function () {
            let _QbHex = pubInputsHex.slice(128, 256);
            let _nonceHex = pubInputsHex.slice(256, 320);
            let _ewHex = pubInputsHex.slice(320);
           
            let _Qb = new Point(
                BigInt("0x" + _QbHex.slice(0, 64)),
                BigInt("0x" + _QbHex.slice(64))
                );
            let _Qs: Point = _Qb.multiply(da);
            let _k = formatSharedKey(bigIntToArray(64, 4, Qs.x));
        
            let _nonce = BigInt("0x" + _nonceHex);
            
            let ewLen = _ewHex.length / 128;
            let _ew: BigInt[] = [];
            for (var i = 0; i < ewLen; i++) {
               _ew.push(BigInt("0x" + _ewHex.slice(i*128, i*128 + 128))) 
            }
        
            let _w = poseidonDecrypt(_ew, _k, _nonce, ewLen);
            expect(_w).to.equal(pArray.concat(qArray));
        }
    );

    it('Testing contracts deadline function',
        async function () {
            let inputSatoshis = rewardSats;
            let utxo = {
                txId: crypto.randomBytes(32).toString('hex'),
                outputIndex: 0,
                script: infoBounty.lockingScript,
                satoshis: inputSatoshis
            };
            let tx = new bsv.Transaction().from(utxo);

            // Should succeed if correct nLockTime.
            tx.nLockTime = contractExpireBlock; // Should be >= contractExpireBlock
            tx.inputs[0].sequenceNumber = 0;    // nSequence needs to be lower than UINT_MAX

            let preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)
            let sig = signTx(tx, new bsv.PrivateKey(da.toString(16), "testnet"), infoBounty.lockingScript, inputSatoshis)

            let context = { tx, inputIndex: 0, inputSatoshis };
            let result = infoBounty.deadline(sig, preimage).verify(context);
            expect(result.success, result.error).to.be.true;

            // Should should fail if nLockTime too low.
            tx.nLockTime = contractExpireBlock - 1; // Should be >= contractExpireBlock

            preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)
            sig = signTx(tx, new bsv.PrivateKey(da.toString(16), "testnet"), infoBounty.lockingScript, inputSatoshis)

            context = { tx, inputIndex: 0, inputSatoshis };
            result = infoBounty.deadline(sig, preimage).verify(context);
            expect(result.success, result.error).to.be.false;
        }
    );

});
