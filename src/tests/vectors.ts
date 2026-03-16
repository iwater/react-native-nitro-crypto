export const vectors: any = {
  "hash": [
    {
      "algorithm": "sha1",
      "input": "",
      "expected": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    },
    {
      "algorithm": "sha1",
      "input": "abc",
      "expected": "a9993e364706816aba3e25717850c26c9cd0d89d"
    },
    {
      "algorithm": "sha1",
      "input": "hello world",
      "expected": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    },
    {
      "algorithm": "sha256",
      "input": "",
      "expected": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      "algorithm": "sha256",
      "input": "abc",
      "expected": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
      "algorithm": "sha256",
      "input": "hello world",
      "expected": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    },
    {
      "algorithm": "sha384",
      "input": "",
      "expected": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    },
    {
      "algorithm": "sha384",
      "input": "abc",
      "expected": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    },
    {
      "algorithm": "sha384",
      "input": "hello world",
      "expected": "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
    },
    {
      "algorithm": "sha512",
      "input": "",
      "expected": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    },
    {
      "algorithm": "sha512",
      "input": "abc",
      "expected": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    },
    {
      "algorithm": "sha512",
      "input": "hello world",
      "expected": "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    },
    {
      "algorithm": "md5",
      "input": "",
      "expected": "d41d8cd98f00b204e9800998ecf8427e"
    },
    {
      "algorithm": "md5",
      "input": "abc",
      "expected": "900150983cd24fb0d6963f7d28e17f72"
    },
    {
      "algorithm": "md5",
      "input": "hello world",
      "expected": "5eb63bbbe01eeed093cb22bb8f5acdc3"
    }
  ],
  "hmac": [
    {
      "algorithm": "sha256",
      "key": "secret",
      "input": "",
      "expected": "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169"
    },
    {
      "algorithm": "sha256",
      "key": "123456",
      "input": "",
      "expected": "b946ccc987465afcda7e45b1715219711a13518d1f1663b8c53b848cb0143441"
    },
    {
      "algorithm": "sha256",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "",
      "expected": "f2559351ce86cfa2f8305eaa71ee9d53ae342cf6c4890e9ce61c6c059f70fc7e"
    },
    {
      "algorithm": "sha256",
      "key": "secret",
      "input": "abc",
      "expected": "9946dad4e00e913fc8be8e5d3f7e110a4a9e832f83fb09c345285d78638d8a0e"
    },
    {
      "algorithm": "sha256",
      "key": "123456",
      "input": "abc",
      "expected": "f6ced6f4883ffc0981a6b9945819f680102b43097ad8ef7a0df9bde06fb3d2e4"
    },
    {
      "algorithm": "sha256",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "abc",
      "expected": "b4b3c22e79e0752a198154470bacb1906eaf35a589e973a30cb1aa3bd747a09a"
    },
    {
      "algorithm": "sha256",
      "key": "secret",
      "input": "hello world",
      "expected": "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a"
    },
    {
      "algorithm": "sha256",
      "key": "123456",
      "input": "hello world",
      "expected": "83b3eb2788457b46a2f17aaa048f795af0d9dabb8e5924dd2fc0ea682d929fe5"
    },
    {
      "algorithm": "sha256",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "hello world",
      "expected": "f869f2cbe98ab22812894e69760c25f9d6401fa1705d332a2c7477883cecfeb1"
    },
    {
      "algorithm": "sha512",
      "key": "secret",
      "input": "",
      "expected": "b0e9650c5faf9cd8ae02276671545424104589b3656731ec193b25d01b07561c27637c2d4d68389d6cf5007a8632c26ec89ba80a01c77a6cdd389ec28db43901"
    },
    {
      "algorithm": "sha512",
      "key": "123456",
      "input": "",
      "expected": "d3f2f066f0da13b4cd51085457a9c50f4dfc3ddc2b790133d49f6a11bd048ab7bf4292abaae52d5c2841f7eda24f51bce0858ef75dd0ee02283c73783d63c6a4"
    },
    {
      "algorithm": "sha512",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "",
      "expected": "e74c2ce79324a3c08008c527f93feab5071d9fd3b5dddef73195180459466630801f7e66da9fc851481fcb0afc959155752257539fa39fa4a3d9c958bf248869"
    },
    {
      "algorithm": "sha512",
      "key": "secret",
      "input": "abc",
      "expected": "18c4d2edb7dc012d4ade387e587ab7c52f50a384529f3e368392a1b0b16183f40a62fe814cba2a049d9b0e72b7aac932006a2f6d77fa7b76aede1bd63d888241"
    },
    {
      "algorithm": "sha512",
      "key": "123456",
      "input": "abc",
      "expected": "7842485b1a55745a9823c3e155986ec9bde5b140691678c5d202a4e1f4664f130ac4fc4dc75c8a51d47b9a8fb43bdcf30652143da696fe79407032ce48aba2f8"
    },
    {
      "algorithm": "sha512",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "abc",
      "expected": "11929b86fc7920dd8a6ca5b70fec75f2e5e351d02ac33303b5ed0998ed13819c72da7628d52e95062b5fe34e5b374eafe59b3c985fdb69ecb954960443ae2b3a"
    },
    {
      "algorithm": "sha512",
      "key": "secret",
      "input": "hello world",
      "expected": "6d32239b01dd1750557211629313d95e4f4fcb8ee517e443990ac1afc7562bfd74ffa6118387efd9e168ff86d1da5cef4a55edc63cc4ba289c4c3a8b4f7bdfc2"
    },
    {
      "algorithm": "sha512",
      "key": "123456",
      "input": "hello world",
      "expected": "6c9c251365f3507dc923023fd8e180925eee0dc0bb467d156edc21b9889fc1115cbd7a948090abb59b31718e83978900d7582993392d90d2835ee13c9f2fbb69"
    },
    {
      "algorithm": "sha512",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "hello world",
      "expected": "42a9296a739f390c2897b69ea227b018990c1e568039db3b3a61d87dda085724b1070148f420bac0b9b326b92e099f367fedd169c6a34ee044f187395bb810ad"
    },
    {
      "algorithm": "md5",
      "key": "secret",
      "input": "",
      "expected": "5c8db03f04cec0f43bcb060023914190"
    },
    {
      "algorithm": "md5",
      "key": "123456",
      "input": "",
      "expected": "cab1380ea86d8acc9aa62390a58406aa"
    },
    {
      "algorithm": "md5",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "",
      "expected": "e9736446c91facb008abf7b966b1657f"
    },
    {
      "algorithm": "md5",
      "key": "secret",
      "input": "abc",
      "expected": "d9bf7c3a63eae7031c4e6d7c9b78ba93"
    },
    {
      "algorithm": "md5",
      "key": "123456",
      "input": "abc",
      "expected": "31c7c3659be95cd3c7c024a14751cf0c"
    },
    {
      "algorithm": "md5",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "abc",
      "expected": "75435c1c26efdeb9444777844cbf4e60"
    },
    {
      "algorithm": "md5",
      "key": "secret",
      "input": "hello world",
      "expected": "78d6997b1230f38e59b6d1642dfaa3a4"
    },
    {
      "algorithm": "md5",
      "key": "123456",
      "input": "hello world",
      "expected": "9028905855a81e0f3f76a72212e6c488"
    },
    {
      "algorithm": "md5",
      "key": "very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_very_long_secret_key_",
      "input": "hello world",
      "expected": "e23a0060bd3139992efcc474d05b4682"
    }
  ],
  "cipher": [
    {
      "algorithm": "aes-128-cbc",
      "key": "8ec5ee96a2e02f90b7064ce4c1c48acb",
      "iv": "a4b48d06cb6229ffd6432098ef7b96fb",
      "input": "",
      "ciphertext": "b441a1f94b4eb472b7b52f4ad65fcb55"
    },
    {
      "algorithm": "aes-128-cbc",
      "key": "97a723846607ddd6336d8e85bf5225d7",
      "iv": "4801b5b4400539fb1e0aea8dc8947ded",
      "input": "abc",
      "ciphertext": "a773bd53fb43bab9145f3581bb7d388c"
    },
    {
      "algorithm": "aes-128-cbc",
      "key": "e68a51dd1c9422cacbeabfd79af94eab",
      "iv": "62899adbd6f84df671b87489019c957b",
      "input": "hello world",
      "ciphertext": "263c913531f7cf10403a090d4e8e1d08"
    },
    {
      "algorithm": "aes-256-cbc",
      "key": "5b9a36522346d76d2b6cd7f34f33a052ae990721dfe58e3ac6f08c9bc5f15b33",
      "iv": "2b8ffcdb219cd034cae505a316ee8f5f",
      "input": "",
      "ciphertext": "db8cf7337a1aead1b6a8105fb2bc7a51"
    },
    {
      "algorithm": "aes-256-cbc",
      "key": "82573b9ee17e6258347dd3566e2276dac7720ca38e67bbf1f4d01fe42b543a1c",
      "iv": "30e2b82f1debeadc610258723b882a4c",
      "input": "abc",
      "ciphertext": "e81a64e8e333fc06177dc9d7988326f5"
    },
    {
      "algorithm": "aes-256-cbc",
      "key": "d9fad73f69787887863be584bbbef2645c9b0dcd850aa5437d7cb112a56b7344",
      "iv": "eabff921933b07e12d2625ed231d73f2",
      "input": "hello world",
      "ciphertext": "edb7ff2b2d864a6391e8c91f6a1c9680"
    },
    {
      "algorithm": "aes-128-gcm",
      "key": "87587e328d26dc523697b1db2bc73110",
      "iv": "d38af5ee97981e972e5137d8",
      "input": "",
      "ciphertext": "",
      "tag": "6455eacda1b99bde2b7a483fc52df168"
    },
    {
      "algorithm": "aes-128-gcm",
      "key": "265debd779b58f577905ca7ed03f5336",
      "iv": "38ebe92e17a2869f1d04d088",
      "input": "abc",
      "ciphertext": "380262",
      "tag": "06be931a6f92575177d83880aabaaaf8"
    },
    {
      "algorithm": "aes-128-gcm",
      "key": "064decc71a289368dbf03ef8f9660ed2",
      "iv": "dc19d8cc8ba5bfb5589f492e",
      "input": "hello world",
      "ciphertext": "f1ac06b1655950581a2cf2",
      "tag": "8389b70b6c51c15c3644196e18efad29"
    }
  ],
  "sign": [
    {
      "algorithm": "rsa-pss-sha256",
      "data": "68656c6c6f20776f726c64",
      "privateKey": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCIMyjKHCfA1vKv\ne5qZz/ud/1g48CA1iY7YaDHUN5hB8PwOg+MOCaCOLYohXJhNH85jZ3JR+sGhzj49\nHlC9XV0ftdmkTz8TvN028h41mWwuJmIPgNWcy7vF/3/ZBwGF7pYI2h6Rg75d9HTj\n2x+S35Paegmgh8ZzJ7IOTeH8lfVrTA4HEI0uePbv/4yxXb8wxyFUYggyxLPJ9947\nMg868yUekM6GIlD5BiyZSYUhhkWg5kOs/gi+yAKCJfyzuPQFFgBODsc8wAT7bd+h\nVicUKdatZ1oIXCTF5wsyAOBZK4/bhktNN2jzYXWE7qLcUYEdPvoEjfB9eaqrQUTX\nWadYVjUBAgMBAAECggEAAv3YrgPLTb2K7BbTcQBz/ubuaaXAl1xzokY7nfUwp3Yj\nGzCDaroEaEsQxyXRBJSnxGAvzyQqX6L3lAEX9ejYlEs6whSphoX19/B+gF/j0+ms\n6rlCN+TztWgkx0ATpPz2F7CuzjRuGIM3lA+qlF/L0BcxIfEJh1r+WrkUNyeWEeq8\nChOCK0cTEy3AtbCUCYWdiRUlKKOngrE4ruvUB5PS55oeTNjnkI8/VCFD/1mpZCEs\n1JRDU4byJmZ2zpnQ3+ofxayuk+VONkDrVLV5WUEk7C0nDqgKBOhrVaImZlZJ9irE\ngU3mPj1/6a66Zyz6qau+lGuKpaWIun0+bCsT0Fr/fwKBgQC8qsdYyV+wT/+Sk3dK\nQOWxXUYKhAtGRM5RiHPi5UcZYfIktPfGc5846NsRgdeOUuLBI4m1ad3pMLPkwLfa\nMuEG+jZHkH7kbasrVKR0KvKDIEnfVzLXir+G18yxCZAsFbdOR2FGbTh7jQ7iqU7K\nTcTCJuEjg/x7arLhkQv3Cu6NXwKBgQC4zs5c5DXvK/2B0Y5MBCCPaFxqM/WZkA7l\nU2s4REUUdtBMR5Il9ZA7Bk+pqpdgShbmyw+B38I7OVQAdn6o8OJsVipwGRzq7LQb\nPvI+kDVtdXL6gPMeSnWiZdrnScss6sInPzTqNoige4oEVDLZMhseURI/BnBnAC7n\nVgrS/jX5nwKBgQCJgVq7LkGMijG2Db5youwFofqLbYOeGkXZDL+RjhOMv2MxN6gi\nvmA8pRINJ3oIZAaaR6F1VAyFiZaDUaZt5Ik3gaOP8xNYv0ly0kTt2eNYiG7u1Wnb\nyGchCyVHnrWyO72W0tVl8/Knsb44mrcvIREXhCiwruCUvsZTOljjG9eTtwKBgFkP\nmNWdSPyk53uLYJbzmjliIr8voRlLGlKb29z20Y+mHoXUK/NNHx/Cz9tFEcRekCDT\nFPsSuUjPPNMoR6vkwklRUQxKnev8/GLw9878sjK42hssz3z2hzAnA9JYdqiDzeMa\nC8cfVsJ4JrAlX4faJMV8bl2fHcYViYUEqxy5U4ujAoGBAJC2TBqI7VKQsWCgsESe\nCXq+RbH2shmtpsFpLpEgyoD2AfKb1h3Q0QPpegJ/aiTaJNN6vtrqBPDcEYcsPm8R\ngTrYWPWg1Im/+am41CEh5pHko6heNeH/Ged3cgq6Acbon2Pqce+OD4RddNCYifyM\nvffwhfwMloYy3jYUsI4/5jiI\n-----END PRIVATE KEY-----\n",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiDMoyhwnwNbyr3uamc/7\nnf9YOPAgNYmO2Ggx1DeYQfD8DoPjDgmgji2KIVyYTR/OY2dyUfrBoc4+PR5QvV1d\nH7XZpE8/E7zdNvIeNZlsLiZiD4DVnMu7xf9/2QcBhe6WCNoekYO+XfR049sfkt+T\n2noJoIfGcyeyDk3h/JX1a0wOBxCNLnj27/+MsV2/MMchVGIIMsSzyffeOzIPOvMl\nHpDOhiJQ+QYsmUmFIYZFoOZDrP4IvsgCgiX8s7j0BRYATg7HPMAE+23foVYnFCnW\nrWdaCFwkxecLMgDgWSuP24ZLTTdo82F1hO6i3FGBHT76BI3wfXmqq0FE11mnWFY1\nAQIDAQAB\n-----END PUBLIC KEY-----\n",
      "signature": "2eed96e379c04edc60238cdc4dd975f44d74570ac671ffe7e27aa6ee54bf16d9830bf9e14bea4d0db735d1b4f2f609db2ab485d981a3b71fb2fa8ba0b43853c88b73d4bb548905d357a2adcbfa3e900a995488692de6b86efe4ccfda69a7727d330115ef6cb14daf8e0f8f8e8f7ba77ef66253808a26bb669c594d2df9b7ce50cd1b7fb060e45df747e5d1eaec0190cabe9dd56bb5e070875c005a576cc0c0358ac44ad7ede076d7f1508d643493e7c7955be4db7e93f20c81b76d484e70b6498a904ecc062563cbd50677f479d5939f6ab05c53bf0d417a70cec0d42666b37cf40c03b39c27449890b63818168e9361af87f06ae45db2e89f936397d1ad252f"
    },
    {
      "algorithm": "ecdsa-sha256",
      "data": "68656c6c6f20776f726c64",
      "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9A2ihuZTTt9neEXO\n70EcIhrUglZnLAYa9jYzIgePW2uhRANCAAQsbxsYPvcK/UGBT/zzeVt0+kQrtCeZ\nTHIV0roge4+aASgsFcTKdpBjIEK1pytJYslR08aEIeDZMJvguRH779VI\n-----END PRIVATE KEY-----\n",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELG8bGD73Cv1BgU/883lbdPpEK7Qn\nmUxyFdK6IHuPmgEoLBXEynaQYyBCtacrSWLJUdPGhCHg2TCb4LkR++/VSA==\n-----END PUBLIC KEY-----\n",
      "signature": "3045022100ceaa554c8c9113fb451f46f86a6cf02051c2f22b1d6ce607fed610e5149faf8402202d068fd1e2bd23a5ab4310156e540b77268bf9fa0680054419cda45fa63256ca"
    },
    {
      "algorithm": "ed25519",
      "data": "68656c6c6f20776f726c64",
      "privateKey": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFxf/o9A9tVOIFnvyRdW9L7lEyadBmrtuLULZnLIyDaQ\n-----END PRIVATE KEY-----\n",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAIRmTxDgg472uwFX4K7pciAb7RGcNdc9fELUvO7bOa8M=\n-----END PUBLIC KEY-----\n",
      "signature": "164364f3940509486b6bcb6ff94a49a6df07592b098fa3b5ea2c6918df115922ff361ec0bfd099c26b8fd10579afc23c764aff69e4e9f214da3142c21c67dc09"
    }
  ],
  "pbkdf2": [
    {
      "params": {
        "password": "password",
        "salt": "salt",
        "iterations": 1,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    },
    {
      "params": {
        "password": "password",
        "salt": "salt",
        "iterations": 1,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b4dbf3a2f3dad3377264bb7b8e8330d4efc7451418617dabef683735361cdc18c"
    },
    {
      "params": {
        "password": "password",
        "salt": "salt",
        "iterations": 1000,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"
    },
    {
      "params": {
        "password": "password",
        "salt": "salt",
        "iterations": 1000,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb388b3b1131f741bcbeb02541c8c2e97bd8bed62ab6425542e45512b7312f440eb"
    },
    {
      "params": {
        "password": "password",
        "salt": "salty_salt",
        "iterations": 1,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "7c12c1d57635b700346d314c110898f8322ea8ea4910ce2172cf0ea310710e4b"
    },
    {
      "params": {
        "password": "password",
        "salt": "salty_salt",
        "iterations": 1,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "7c12c1d57635b700346d314c110898f8322ea8ea4910ce2172cf0ea310710e4b27ef95a7cc7292b493582e7a273ca45634cd872c7edf9d33dfcb951507c5771d"
    },
    {
      "params": {
        "password": "password",
        "salt": "salty_salt",
        "iterations": 1000,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "15ad943af6ceebecbc54dd59b1a55b52c997fcdd91b7e0e39d621496562827d6"
    },
    {
      "params": {
        "password": "password",
        "salt": "salty_salt",
        "iterations": 1000,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "15ad943af6ceebecbc54dd59b1a55b52c997fcdd91b7e0e39d621496562827d6f099f76a7e15e5688482b14f686e99348e6d44c5c55216de7c7f52002b53aeeb"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salt",
        "iterations": 1,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "38df428b309308e48c3687e7f90bda0e9cf253568c21ec754a0e076ab4ab6423"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salt",
        "iterations": 1,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "38df428b309308e48c3687e7f90bda0e9cf253568c21ec754a0e076ab4ab642385742c539f7ebe7851764a826224b4072e1d379f164b20ff897a16b3feb0e413"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salt",
        "iterations": 1000,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "a8df899f3c4f204d967e0ad63c092987c10055ebb017b3d9d28add218d4f7aad"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salt",
        "iterations": 1000,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "a8df899f3c4f204d967e0ad63c092987c10055ebb017b3d9d28add218d4f7aadc8c69da6f0a1537dd5de8357f8e0b0ae5cf9c47db84b60e9d2978606ee13d2e3"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salty_salt",
        "iterations": 1,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "393b189765a54ab5d25a9fe7a3628d0052a3d399a60a9c9a3a76aa6aa12fa5bf"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salty_salt",
        "iterations": 1,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "393b189765a54ab5d25a9fe7a3628d0052a3d399a60a9c9a3a76aa6aa12fa5bf569e963b8d666c4b7d94453635de96c78d612f066ab7b2f97e614fb82340c596"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salty_salt",
        "iterations": 1000,
        "keylen": 32,
        "digest": "sha256"
      },
      "expected": "7453571594bb7cbd17d4efb6a77c0bbd8b4f010a39de3a947240348557abe923"
    },
    {
      "params": {
        "password": "secret",
        "salt": "salty_salt",
        "iterations": 1000,
        "keylen": 64,
        "digest": "sha256"
      },
      "expected": "7453571594bb7cbd17d4efb6a77c0bbd8b4f010a39de3a947240348557abe9233c7afcca36489ffd92aaaf6e045ac6bde21798af0104546b53121fec8f43fecc"
    }
  ],
  "scrypt": [
    {
      "params": {
        "password": "password",
        "salt": "salt",
        "keylen": 64,
        "N": 16384,
        "r": 8,
        "p": 1
      },
      "expected": "745731af4484f323968969eda289aeee005b5903ac561e64a5aca121797bf7734ef9fd58422e2e22183bcacba9ec87ba0c83b7a2e788f03ce0da06463433cda6"
    }
  ],
  "hkdf": [
    {
      "algorithm": "sha256",
      "ikm": "ikm",
      "salt": "salt",
      "info": "info",
      "length": 32,
      "expected": "fe8f9615d2374c0d17f77d1aeaf408c2e75fe0466073d0def23c733e2f862dfd"
    },
    {
      "algorithm": "sha256",
      "ikm": "ikm",
      "salt": "salt",
      "info": "context",
      "length": 32,
      "expected": "27e078ad00e5401656ebf036ffcec2a5674c73a5d2f0a8df51923f65d2cde467"
    },
    {
      "algorithm": "sha256",
      "ikm": "ikm",
      "salt": "",
      "info": "info",
      "length": 32,
      "expected": "253471d1d21137fd9a4016868ba773216954d4cc5ecb925eeacadfd7eeb208c3"
    },
    {
      "algorithm": "sha256",
      "ikm": "ikm",
      "salt": "",
      "info": "context",
      "length": 32,
      "expected": "296de78ab4122dbd998fdbd7ca06238a705441c743a4389b98054e8a5c4b3867"
    },
    {
      "algorithm": "sha256",
      "ikm": "input_key_material",
      "salt": "salt",
      "info": "info",
      "length": 32,
      "expected": "d201aab5d13fca495f1c804a8b54f4701914c020389d79ed1edb813ce9a22370"
    },
    {
      "algorithm": "sha256",
      "ikm": "input_key_material",
      "salt": "salt",
      "info": "context",
      "length": 32,
      "expected": "a48bc8623be8dc443cc8dc748f420241b7a22da67d00e67e0584b9948df22cdf"
    },
    {
      "algorithm": "sha256",
      "ikm": "input_key_material",
      "salt": "",
      "info": "info",
      "length": 32,
      "expected": "2ab29ca7813c5e50c09de8e8b840acd9e5b479473ef376017cca9922657cebdd"
    },
    {
      "algorithm": "sha256",
      "ikm": "input_key_material",
      "salt": "",
      "info": "context",
      "length": 32,
      "expected": "804cd424d24f15fa0ecc3857b6b7c62980304116f44d12547fe40964139fb0fe"
    }
  ],
  "asymmetric_enc": [
    {
      "algorithm": "rsa-oaep",
      "privateKey": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC224MBWVLaVRcH\noyfJSbu7cVbVEhKPvzU23bASQS/LiIrFgEce2rMm0tNDDgIKorccAMIDEGLpLBGW\ns35wKOZsQqIg0Wp5fhkTN4sZZfLJnQc9NuWR9wQ87PkdQFI89+LGOh72IM8UrgYD\nkHLONP+VCFhDIn6G0nynZSCEBVhr9ZKX2lr2rcZqH2xlb08qxhUH9K5gbyBBOgq2\n4Nkw/gLLBKzfEsS90atpqK4jXApkDp/gDwYktANSXZuT9G4SnwQdFrQ/zNnRbApC\nnDtW0qQbBNwxGGm6XJxvJGCFcu5nOokzzWr164yhdl+9eFkNhN0qfa2++rxqtDY6\nfou52UkbAgMBAAECggEACKTTyoqIah2/mvLRfKhpoXC4JBZYnkbxowhTvGksczif\nJrrrob/A3EL3DaJp4krS0RYQFcj+g/s7UZ5mibLFQbTcqSR9HgUh9lCX2LmDApjT\nsMcZjw7YOnERTZquyIcHR0uUDxp574ZSbnSzmJ/UvRzJ31KQHJtynQ8gvFzsUx4S\nO7vngVD+VZUKGrFDkY92PwHYKZ0bhV4XdqLRiYjgJUEUEPlD9s3cXDVT6w9rlQkp\n9/aoOA615SVopksaLbxfhnrWpND35oWebkaJJrnREGJ5eHrv7AAYHRg84n+dpmmd\nI/hOTpoRa4IAZjO/rSAtmchbifV/BjMiUCl/rDzc0QKBgQDdz2rY+pTHOyw9Xzf+\nRAPyYQkNkdi/qGGk8xFxe1Jpki+X8cVVf7GDNDcLrSp5VpvLF9GOMzF5OvzgNODu\nZCKi/XbVKe7MODWGPzDac9eWmfW6cUSRX2o3wIaSvCeKwjzyh62IyA+JhOweHSAf\nARM3x2hPJkTHye91wd1lQqscbQKBgQDTCwb0vr32irmyROeipBH5ysatPzH3SDoA\nj4/tjCdpHknRKa40PHzGseqZq6E8ETAlLKvaOACki8izyy6QTex9+ZUzkNvYbKFd\ng8C0PiDqnbBHrpsgAQoutN4YQuPrU71WFkW0/GnPauzDgpWNGyowtg0phPVWU5NL\nWrtGtu32pwKBgQCL1mkxNAE5/ZctdetSFMU8OGrBsFIqulgc6tTza2EQh4YTz+ut\ntFxQMEoHxXtClhSQHIsTkDi/ii3El/G6uUyQ3yTczJvtCf7MjOgawO+I1bVyflhR\nIgtP7MOqnI59T2mnKVyBIEeTVkaZ0ZjfkwjvoHqlc6XnIushnUAbx8UinQKBgHEn\nsXQarXn6SbS200fWFrlLKxmLD7xZopfYYcBpbFwlXEjkwz3IzNIwZOw+JPYy9RCJ\nkh8v9dBEDrmwEGhZD5s/7eq3GdlB7YdZdEJwKXACWpkkmpIfXJlMauSxQMlVnegB\niyCOUiFfYFE3u/3recSiaA5B9tVxfEFkBZPV02NzAoGAYtLuoAhnptd5UG6dXcc8\ndupkQO9UdINGGeJ2vfjSMQRJCBMUOVbV57YzaKYmZwoIbRjnXPgZDtJnVMzvpyF1\nr8DdtW6TMQEszQybPAJMnm55MIaERuqoQ19thAiwNmF9FLADgGLrkJMBuMxle4gq\n0QmiVMtUaF+B5Y/yU+T1E2c=\n-----END PRIVATE KEY-----\n",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAttuDAVlS2lUXB6MnyUm7\nu3FW1RISj781Nt2wEkEvy4iKxYBHHtqzJtLTQw4CCqK3HADCAxBi6SwRlrN+cCjm\nbEKiINFqeX4ZEzeLGWXyyZ0HPTblkfcEPOz5HUBSPPfixjoe9iDPFK4GA5ByzjT/\nlQhYQyJ+htJ8p2UghAVYa/WSl9pa9q3Gah9sZW9PKsYVB/SuYG8gQToKtuDZMP4C\nywSs3xLEvdGraaiuI1wKZA6f4A8GJLQDUl2bk/RuEp8EHRa0P8zZ0WwKQpw7VtKk\nGwTcMRhpulycbyRghXLuZzqJM81q9euMoXZfvXhZDYTdKn2tvvq8arQ2On6LudlJ\nGwIDAQAB\n-----END PUBLIC KEY-----\n",
      "data": "736563726574206d657373616765",
      "ciphertext": "94d1e6c4fb01e8510c25255d2378c569fe11e9b508cf6b9b64c85f1ef99fc40cfdc9f4f68df67d4c60177f0e71198863af162a7d35622770fb26316918a210dc6f2b768078ef53e9b77b02568b75faf0436f9ce4b9768871830df45434e02c579ecd6f693761d215e2b2ea8a569e2967c9941e835b5b76f4792ea7a815e46f7df61fea53c53a775fe7c6ceca962ffa1611b90604d3d1877ee778cc498d678b554e5814c507c82ab6f10a6991a81e178e8ac7f20f97e273e53f0bfe261c706359b5d1919aef7ae8a2e04d53dd24a2ca5fe7aedae9bd795274ea2f1525976c266d47c7e021770510b9a947a992cae3e776f47751b2fbfc1b23758aac9679b0e1bc"
    }
  ],
  "key_agreement": [
    {
      "algorithm": "ecdh-p256",
      "curve": "prime256v1",
      "privateKey": "5249e2367c8e78b87f2bb7622f2d6d9469cb1276407ae64a63680fb5939d1df3",
      "otherPublicKey": "04ffa0e9ab090c74ad64a57a00214506aee1f4629800326a3e89d796d913b79a2af4ca3022d02a6e26cf580dfce2dce8f27f1d9f5f505285cb1359701c0bf05855",
      "expectedSecret": "69ac3f7c1471ee80a4f5039cf9c01a93264403a26f6e589f197e650ebab9e170"
    },
    {
      "algorithm": "x25519",
      "privateKey": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIGC+54CM1HZqkAQ54/JaV0N2G3d9dE9h3xJ1+earCD1v\n-----END PRIVATE KEY-----\n",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEATCvboxcaMN9j385x9q0LPVYQJNg1T3fmO2J7zbSuPWo=\n-----END PUBLIC KEY-----\n",
      "rawPrivateKey": "60bee7808cd4766a900439e3f25a5743761b777d744f61df1275f9e6ab083d6f",
      "rawOtherPublicKey": "4c2bdba3171a30df63dfce71f6ad0b3d561024d8354f77e63b627bcdb4ae3d6a",
      "expectedSecret": "7369be7c1348c46448d3df99c567e7658695dfd5bc18e8bff4ea9996ccda4840"
    }
  ],
  "aes_kw": [
    {
      "kek": "75b16ae1b95684e911d86250cb0b2529",
      "plaintext": "346f5f4031157bc34b1559fea04c0285cb4bdb860a829693",
      "wrapped": "30103e889e0bb2151d64c4d691c1933c20b0d8d22f48877a3c3253cc73f0be9e"
    }
  ],
  "x509": [
    {
      "certificate": "-----BEGIN CERTIFICATE-----\nMIIDBzCCAe+gAwIBAgIUOJL6XJDKV9jiC7Y9YJrxTUCtrLgwDQYJKoZIhvcNAQEL\nBQAwEzERMA8GA1UEAwwIVGVzdENlcnQwHhcNMjUxMjE0MTgzMzEzWhcNMjYxMjE0\nMTgzMzEzWjATMREwDwYDVQQDDAhUZXN0Q2VydDCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAMAJegjUnZchGqctBZsPoFC9eI4edfS+yne/4IWPLXDP+/h/\nQBr98qlsXzjY5aD7feljUPEfKD1CAqhV/oTzFatxSp/e4awb5iYm2myEfu9ZQX03\niXH2wl6stL0w9hqAxRQ9lgKa6dG5Cz6mV28e8RwqzpgGr+wiu3wS8dWFlvBN/Aqy\nqw68sa0supvpo8C59BPpGrEa+XQpgUHx7qYNHP+rt2BwcRZX8blOa5G5O85tFlNJ\ndP2InGBkI1Z59lo6cNhBXmweugI7JM39R4bAIRPd2vKHBldXlR1QPThtI6cDYcWM\n9Y55yK0ubPtRF4Ecfof+fCVSZH8UTnwa3iC1EF0CAwEAAaNTMFEwHQYDVR0OBBYE\nFA2BLkGFwa/89KER9KnWhKN9wrdIMB8GA1UdIwQYMBaAFA2BLkGFwa/89KER9KnW\nhKN9wrdIMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJceeHJ4\nhHP785L4t+DsWUZLolayt4xEC1IMsRUzrt8YHP9x7dkJZQHOO4Xd7PYngbXnlb45\nMiE5JHkMDFuO52pftA7pk747OiBzk615JVWHjqoEt6Xu8XUpQ/u7HpeUn6/WiRcO\nJxvg2ypWh6TpswRzvxR2smAyoYn1tE+zNWPe2abHSyrIPHLghFBxKPQRHgbMbNX4\nbOGI8EdPRPCig7Ihaiopta9mF4AkjNspD4SSZOPnNvgYOKiNvV3yHf8m1GgFacje\nYeenUjJFVMVf9bjNjm6gWLHDPwenM6pDJUBX2WV2X98seEEtwH/rjrwAke+m8gyE\nE9g9cDYfF9bv3yQ=\n-----END CERTIFICATE-----\n",
      "subject": "CN=TestCert",
      "issuer": "CN=TestCert"
    }
  ],
  "dh_details": [
    {
      "prime": "a20cc898e22ce3d736d014def91d964a2cc0e4c94ff7ee0bbe58a4833884d05938533c5b26596071c17ccc722d995236c7ee2c1a3afc61591784fadf890904bae8be9e3df709e0c7e5e9a2960c81f1b34f225b27fa989d3f7a848a8ce9069bda7b36c6311a0964877dab137d9f24c58e82987121a49c1079aa91d9cdb16605af",
      "generator": "02",
      "publicKey": "212b0509536b127c878e4bbc67667aa5404d846fce49a8918dd39194b941601d5af355b98172197963b2090a434cfb14aae8d2420752d2300c178d1723b9287f76c88a51c76534fc5b47142e7e2c8ae3abb8958f19314c461664f73805f432d40b3c079b5a120617a196edf05929aa8c1d56aea5203ebb511ad836d8722c49d3"
    }
  ],
  "aead_enc": [
    {
      "algorithm": "aes-256-gcm",
      "key": "37188ab2c2f0a74efd342ef2e541e660e415aa8142fe84e1cbae2f3f55c413c4",
      "iv": "d77e71d48ca3f934c3afef1a",
      "aad": "6164646974696f6e616c2064617461",
      "plaintext": "736563726574207061796c6f6164",
      "ciphertext": "06f5e12c7e0605a95239089fe25f",
      "tag": "ba4c228257ecb7275af1057ef21ea025"
    },
    {
      "algorithm": "chacha20-poly1305",
      "key": "803b31084ed16300aad127385a6046f24a5c8ae6e4828577f87aea9ab6303590",
      "iv": "510b90748523a0f6cace915f",
      "aad": "616164",
      "plaintext": "7061796c6f6164",
      "ciphertext": "317bd1a8e33121",
      "tag": "1fb7d06d844f87d3eb5cb492e4574fc2"
    }
  ]
};
