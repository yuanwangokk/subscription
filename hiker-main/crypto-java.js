(function() {
    //by LoyDgIk
    const jvString = java.lang.String;
    const jvArray = java.lang.reflect.Array;
    const Byte = java.lang.Byte;
    const Integer = java.lang.Integer;

    const StandardCharsets = java.nio.charset.StandardCharsets;
    const MessageDigest = java.security.MessageDigest;
    const Base64 = android.util.Base64;
    const StringBuffer = java.lang.StringBuffer;

    const Cipher = javax.crypto.Cipher;
    const IvParameterSpec = javax.crypto.spec.IvParameterSpec;
    const SecretKeySpec = javax.crypto.spec.SecretKeySpec;
    const FileUtil = com.example.hikerview.utils.FileUtil;

    //CryptoUtil
    //互转类
    function Data(bytes) {
        this.bytes = bytes;
        //this.length = bytes.length;
    }

    Object.assign(Data, {
        parseStr(str, charset) {
            return new Data(toJvString(str).getBytes(charset));
        },
        parseUTF8(str) {
            return Data.parseStr(str, StandardCharsets.UTF_8);
        },
        parseUTF16(str) {
            return Data.parseStr(str, StandardCharsets.UTF_16);
        },
        parseHex(str) {
            return new Data(hexDecodeToByteArray(str));
        },
        parseBase64(str, flags) {
            return new Data(base64DecodeToByteArray(str, flags));
        },
        parseLatin1(str) {
            return Data.parseStr(str, StandardCharsets.ISO_8859_1);
        },
        parseUTF16LE(str) {
            return Data.parseStr(str, StandardCharsets.UTF_16LE);
        },
        parseInputStream(stream) {
            return new Data(FileUtil.toBytes(stream));
        }
    });
    Object.assign(Data.prototype, {
        toHex() {
            return bytesToHex(this.bytes);
        },
        toBytes() {
            return this.bytes;
        },
        toString(charset) {
            return bytesToString(this.bytes, charset);
        },
        toLatin1() {
            return this.toString(StandardCharsets.ISO_8859_1);
        },
        toUTF16LE() {
            return this.toString(StandardCharsets.UTF_16LE);
        },
        toUTF16() {
            return this.toString(StandardCharsets.UTF_16);
        },
        toBase64(flags) {
            return String(Base64.encodeToString(this.bytes, flags || Base64.DEFAULT));
        },
        toDigest() {
            return new Digest(this);
        },
        toInputStream() {
            return FileUtil.toInputStream(this.bytes);
        },
        toUint8Array() {
            let length = this.bytes.length;
            let u8Arr = new Uint8Array(length);
            for (let i = 0; i < length; i++) {
                u8Arr[i] = this.bytes[i];
            }
            return u8Arr;
        },
        base64Decode(flags) {
            this.bytes = base64DecodeToByteArray(this.toString(), flags);
            return this;
        },
        base64Encode(flags) {
            this.bytes = base64EncodeToByteArray(this.bytes, flags);
            return this;
        },
        length() {
            return this.bytes.length;
        }
    });
    //摘要类
    function Digest(data) {
        this.data = data;
    }
    Digest.digest = function(data, algorithm) {
        try {
            let md = MessageDigest.getInstance(algorithm);
            md.update(data.toBytes());
            let hashInBytes = md.digest();
            return String(bytesToHex(hashInBytes));
        } catch (e) {
            throw (e);
        }
    }
    Object.assign(Digest.prototype, {
        md5() {
            return Digest.digest(this.data, "MD5");
        },
        sha256() {
            return Digest.digest(this.data, "SHA-256");
        },
        md2() {
            return Digest.digest(this.data, "MD2");
        },
        sha1() {
            return Digest.digest(this.data, "SHA-1");
        },
        sha512() {
            return Digest.digest(this.data, "SHA-512");
        },
        sha384() {
            return Digest.digest(this.data, "SHA-384");
        }
    });


    function process(operation, cipherType, input, key, option) {
        option = option || {};
        validate(key, option.mode, cipherType);
        if (typeof input === "string") {
            input = operation === Cipher.ENCRYPT_MODE ? Data.parseUTF8(input) : Data.parseBase64(input);
        }
        let secretKey = new SecretKeySpec(key.toBytes(), cipherType);
        let cipher = Cipher.getInstance(option.mode || cipherType);
        if (option.iv != null) {
            cipher.init(operation, secretKey, new IvParameterSpec(option.iv.toBytes()));
        } else {
            cipher.init(operation, secretKey);
        }
        return new Data(cipher.doFinal(input.toBytes()));
    }

    const AES = {
        encrypt(data, key, option) {
            return process(Cipher.ENCRYPT_MODE, "AES", data, key, option);

        },
        decrypt(data, key, option) {
            return process(Cipher.DECRYPT_MODE, "AES", data, key, option);
        }
    }

    const DES = {
        encrypt(data, key, option) {
            return process(Cipher.ENCRYPT_MODE, "DES", data, key, option);
        },
        decrypt(data, key, option) {
            return process(Cipher.DECRYPT_MODE, "DES", data, key, option);
        }
    }

    const DESede = {
        encrypt(data, key, option) {
            return process(Cipher.ENCRYPT_MODE, "DESede", data, key, option);
        },
        decrypt(data, key, option) {
            return process(Cipher.DECRYPT_MODE, "DESede", data, key, option);
        }
    }

    function validate(key, mode, cipherType) {
        if (key == null) {
            throw new Error("Key must not be null or empty.");
        }
        if (mode && !mode.startsWith(cipherType)) {
            throw new Error("Invalid mode.");
        }
        let expectedKeyLength = [];
        switch (cipherType) {
            case "AES":
                expectedKeyLength = [16, 24, 32];
                break;
            case "DESede":
                expectedKeyLength = [24];
                break;
            case "DES":
                expectedKeyLength = [8];
                break;
            default:
                throw new Error("Invalid cipher type.");
        }
        if (!expectedKeyLength.includes(key.length())) {
            throw new Error("Invalid key length. Key length must be " + expectedKeyLength.join(" or ") + " bytes for " + cipherType + ".");
        }
    }


    /*mode
    AES/CBC/PKCS5Padding
    AES/CBC/NoPadding
    AES/ECB/PKCS5Padding
    AES/ECB/NoPadding
    AES/CFB/NoPadding
    AES/CFB/PKCS5Padding
    AES/OFB/NoPadding
    AES/OFB/PKCS5Padding
    AES/CTR/NoPadding
    AES/CTR/PKCS5Padding

    DES/CBC/PKCS5Padding
    DES/CBC/NoPadding
    DES/ECB/PKCS5Padding
    DES/ECB/NoPadding
    DES/CFB/NoPadding
    DES/CFB/PKCS5Padding
    DES/OFB/NoPadding
    DES/OFB/PKCS5Padding
    DES/CTR/NoPadding
    DES/CTR/PKCS5Padding

    */
    function bytesToString(bytes, charset) {
        return String(new jvString(bytes, charset || StandardCharsets.UTF_8));
    }

    function base64EncodeToByteArray(bytes, flags) {
        return Base64.encode(bytes, flags || Base64.DEFAULT);
    }

    function base64DecodeToByteArray(str, flags) {
        if (str == null) {
            return null;
        }
        return Base64.decode(str, flags || Base64.DEFAULT);
    }

    function hexDecodeToByteArray(cipherText) {
        cipherText = String(cipherText);
        let str = cipherText.toLowerCase();
        let length = str.length;
        let bArr = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, length / 2);
        for (let i = 0, o = 0; i < length; i += 2, o++) {
            let a = str[i + 1],
                b = str[i];
            if (b != "0") {
                a = b + a;
            }
            let hexInt = Integer.parseInt(new jvString(a), 16);
            let inty = hexInt > 127 ? hexInt - 255 - 1 : hexInt;
            bArr[o] = inty;
        }
        return bArr;
    }


    function bytesToHex(data) {
        let strBuffer = new StringBuffer();
        for (let i = 0; i < data.length; i++) {
            //strBuffer.append(Integer.toHexString(0xff & data[i]));
            strBuffer.append(jvString.format("%02x", Byte(data[i])));
        }
        return String(strBuffer.toString());
    }


    function toJvString(str) {
        if (typeof str === "string") {
            return new jvString(str);
        } else {
            return str;
        }
    }
    $.exports = {
        Data,
        Digest,
        AES,
        DES,
        DESede
    };
})()
