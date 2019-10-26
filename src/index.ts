import { randomBytes, createHmac, createCipheriv, createDecipheriv, createHash } from "crypto";
import axios from "axios";
import os from "os";
import path from "path";
import fs from "fs";

const socketPath = path.join(os.homedir(), ".kr", "krd.sock");

const getSignature = async (fileIdentifier: string) => {
    if (fileIdentifier.length > 256) {
        throw new Error("fileIdentifier too long!");
    }
    const request_id = randomBytes(10).toString("hex");
    let dataHex = "0000002000b7118d3ae607fdc55a640a2ebf91dd528770527f47620c5d8000c1388698bf3200000004726f6f740000000e7373682d636f6e6e656374696f6e000000097075626c69636b657901000000077373682d727361";

    // replace "root" by the fileIdentifier
    const n = (`0${fileIdentifier.length.toString(16)}`).substr(-2);
    dataHex = dataHex.replace(/04726f6f74/, `${n}` + Buffer.from(fileIdentifier).toString("hex"));
    const data = Buffer.from(dataHex, "hex");

    console.log(`KRCrypt ▶ Phone approval required for "${fileIdentifier}". Respond using the Krypton app`);

    const meResponse = await axios({
        method: "GET",
        socketPath: socketPath,
        headers: {
            "content-type": "application/json",
        },
        url: "/pair",
    });

    const public_key_fingerprint = createHash("sha256").update(Buffer.from(meResponse.data.public_key_wire, "base64")).digest("base64");
    const response = await axios({
        method: "PUT",
        socketPath: socketPath,
        headers: {
            "content-type": "application/json",
        },
        url: "/enclave",
        data: {
            "request_id": request_id,
            "unix_seconds": Math.round(Date.now() / 1000),
            "v": "2.4.15",
            "a": true,
            "sign_request": {
                "data": data.toString("base64"),
                "public_key_fingerprint": public_key_fingerprint,
                "host_auth": {
                    "host_key": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNu8lEKwgtomdyjZjh+pIp0K2KVEo/0GdLq8YkuMVkdACPobIFOdRJVIzLn+GK0gQHWG3OrXdkB3W7d+USvSBg=",
                    "signature": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIFpm6jHaalWESMhIhFo3ZCkxiUYRQzx4zyrBQbgBMevmAAAAIQDkdMJzqEVNQBifB7jHN4pXV153RsETc/RX3k4XuL/9QQ==",
                    "host_names": ["KRCrypt"]
                }
            }
        }
    });

    if (response.data.sign_response.error !== undefined) {
        throw new Error(response.data.sign_response.error);
    }

    return response.data.sign_response.signature;
}

const deriveKey = (baseKey: Buffer, content: string, hash: string, size: number): Buffer => {
    return createHmac(hash, baseKey)
        .update(content)
        .digest()
        .slice(0, size);
}

interface IKey {
    fileIdentifier: string,
    key: Buffer,
}

const getKey = async (fileIdentifier: string, optionalHashedPassword: string = ""): Promise<IKey> => {
    const signature = await getSignature(fileIdentifier);
    const signatureBuffer = Buffer.from(signature, "base64");

    return {
        fileIdentifier,
        key: deriveKey(signatureBuffer, `key:${optionalHashedPassword}`, "sha256", 32),
    }
}

const encrypt = async (inFile: string, keys: IKey) => {
    return new Promise<void>((resolve) => {
        const iv = randomBytes(12);
        const cipher = createCipheriv("id-aes256-GCM", keys.key, iv);

        const input = fs.createReadStream(`${inFile}`);
        const output = fs.createWriteStream(`${inFile}.krcrypted`);
        input.pipe(cipher).pipe(output, { end: false })

        cipher.on("end", () => {
            const authTag = (cipher as any).getAuthTag();
            const extraData = Buffer.concat([
                iv,
                authTag,
                Buffer.from(keys.fileIdentifier),
                Buffer.alloc(4),
            ]);

            extraData.writeUInt32LE(keys.fileIdentifier.length, extraData.length - 4);

            output.write(extraData, (err) => {
                if (err) {
                    throw err;
                }
                output.end(() => {
                    resolve();
                });
            });
        });
    });
}

const readTagAndIdentifier = async (inFile: string) => {
    const stats = fs.statSync(`${inFile}`);

    return new Promise<{
        iv: Buffer;
        tag: Buffer;
        identifier: string;
        end: number;
    }>((resolve) => {
        const stream = fs.createReadStream(`${inFile}`, {
            start: Math.max(0, stats.size - 1024),
            end: stats.size
        });
        stream.on("data", (data: Buffer) => {
            let position = data.length;
            const identifierLen = data.readUInt32LE(position - 4);
            position -= 4;
            const identifier = data.slice(position - identifierLen, position).toString();
            position -= identifierLen;
            const tag = data.slice(position - 16, position);
            position -= 16;
            const iv = data.slice(position - 12, position);
            position -= 12;

            return resolve({
                iv,
                tag,
                identifier,
                end: position - 1,
            });
        });
        stream.resume();
    });
};

const decrypt = async (inFile: string) => {
    const d = await readTagAndIdentifier(inFile);
    const keys = await getKey(d.identifier);

    return new Promise<void>((resolve) => {
        const decipher = createDecipheriv("id-aes256-GCM", keys.key, d.iv);
        (decipher as any).setAuthTag(d.tag);
        const input = fs.createReadStream(`${inFile}`, {
            start: 0,
            end: d.end,
        });
        const output = fs.createWriteStream(inFile.endsWith(".krcrypted") ? inFile.replace(/\.krcrypted$/, "") : `${inFile}.krdecrypted`);
        input.pipe(decipher).pipe(output).on("close", () => {
            resolve();
        });
    });
}

const printUsage = (errorStr: string = "") => {
    if (errorStr) {
        console.error(errorStr);
    }
    console.log("usage:")
    console.log("encryption: node krcrypt.js encrypt [identifier] [file]")
    console.log("decryption: node krcrypt.js decrypt [file]")
}

(async () => {
    try {
        const operation = `${process.argv[2]}`;
        const identifier = `${process.argv[3]}`;
        const file = `${process.argv[4] || process.argv[3]}`;

        if (["decrypt", "encrypt"].indexOf(operation) === -1) {
            return printUsage("Invalid operation");
        }

        if (!/^[\x00-\x7F]*$/.test(identifier)) {
            return printUsage(`Identifier can't contain non-ascii characters!`);
        }

        if (identifier.length > 255) {
            return printUsage(`Identifier can't be that long!`);
        }

        if (!fs.existsSync(file)) {
            return printUsage(`File "${file}" doesnt exist!`);
        }

        if (operation === "decrypt") {
            await decrypt(file);
            console.log(`KRCrypt ▶ File successfully decrypted!`);
        }

        if (operation === "encrypt") {
            const key = await getKey(identifier);
            await encrypt(file, key);
            console.log(`KRCrypt ▶ File successfully encrypted!`);
        }
    } catch (error) {
        if (error.response) {
            console.log(JSON.stringify(error.response.data, null, 4));
        }
        console.error(error.message);
    }
})();
