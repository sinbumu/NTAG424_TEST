const crypto = require('crypto');
const { Buffer } = require('buffer');

class InvalidMessage extends Error {}

const EncMode = {
    AES: 0,
    LRP: 1  // LRP would require a custom implementation or third-party library.
};

const ParamMode = {
    SEPARATED: 0,
    BULK: 1
};

function getEncryptionMode(piccEncData) {
    if (piccEncData.length === 16) return EncMode.AES;
    if (piccEncData.length === 24) return EncMode.LRP; // Example case
    throw new InvalidMessage("Unsupported encryption mode.");
}

function decryptSunMessage(paramMode, sdmMetaReadKey, sdmFileReadKey, piccEncData, sdmmac, encFileData = null) {
    const mode = getEncryptionMode(piccEncData);
    let decryptedData, fileData;

    if (mode === EncMode.AES) {
        const decipher = crypto.createDecipheriv('aes-128-cbc', sdmMetaReadKey, Buffer.alloc(16, 0));
        decryptedData = Buffer.concat([decipher.update(piccEncData), decipher.final()]);
    } else {
        // LRP decryption logic needs to be implemented based on the specific protocol.
        throw new InvalidMessage("LRP decryption not implemented.");
    }

    const piccDataTag = decryptedData.slice(0, 1);
    const uidMirroringEn = (piccDataTag[0] & 0x80) === 0x80;
    const sdmReadCtrEn = (piccDataTag[0] & 0x40) === 0x40;
    const uidLength = piccDataTag[0] & 0x0F;
    let uid, readCtr, readCtrNum;

    if (uidLength !== 0x07) {
        throw new InvalidMessage("Unsupported UID length");
    }

    const dataStream = Buffer.alloc(0);

    if (uidMirroringEn) {
        uid = decryptedData.slice(1, 1 + uidLength);
        Buffer.concat([dataStream, uid]);
    }

    if (sdmReadCtrEn) {
        readCtr = decryptedData.slice(1 + uidLength, 4 + uidLength);
        Buffer.concat([dataStream, readCtr]);
        readCtrNum = readCtr.readUInt32LE();
    }

    if (!uid) {
        throw new InvalidMessage("UID cannot be None.");
    }

    const fileKey = sdmFileReadKey(uid);

    if (encFileData) {
        if (!readCtr) {
            throw new InvalidMessage("SDMReadCtr is required to decipher SDMENCFileData.");
        }
        // Assuming decryptFileData function is implemented correctly elsewhere
        fileData = decryptFileData(fileKey, dataStream, readCtr, encFileData, mode);
    }

    return {
        piccDataTag,
        uid,
        readCtr: readCtrNum,
        fileData,
        encryptionMode: mode
    };
}

// Implement CMAC and other required functions based on your needs

module.exports = { decryptSunMessage };