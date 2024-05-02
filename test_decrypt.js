const { decryptSunMessage } = require('./decode');

// 테스트 데이터 설정
const paramMode = { SEPARATED: 0 };  // 예시 Enum 설정
const sdmMetaReadKey = Buffer.from('00000000000000000000000000000000', 'hex');
const piccEncData = Buffer.from("FD91EC264309878BE6345CBE53BADF40", 'hex');
const sdmmac = Buffer.from("ECC1E7F6C6C73BF6", 'hex');
const encFileData = Buffer.from("CEE9A53E3E463EF1F459635736738962", 'hex');
const sdmFileReadKey = _ => Buffer.from('00000000000000000000000000000000', 'hex');  // Mock 함수

// 함수 호출
const result = decryptSunMessage(
    paramMode.SEPARATED,
    sdmMetaReadKey,
    sdmFileReadKey,
    piccEncData,
    sdmmac,
    encFileData
);

// 결과 확인
console.log("Test Result:", result);
console.log("PICC Data Tag:", result.piccDataTag.toString() === '\xc7' ? 'Pass' : 'Fail');
console.log("UID:", result.uid.toString('hex') === '04958caa5c5e80' ? 'Pass' : 'Fail');
console.log("Read Counter:", result.readCtr === 8 ? 'Pass' : 'Fail');
console.log("File Data:", result.fileData.toString() === 'xxxxxxxxxxxxxxxx' ? 'Pass' : 'Fail');
console.log("Encryption Mode:", result.encryptionMode === 0 ? 'Pass' : 'Fail');  // 0는 AES를 가정
