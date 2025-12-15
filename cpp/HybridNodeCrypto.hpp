#pragma once
#include "HybridNitroNodeCryptoSpec.hpp"
#include "MLKEMKeyPairResult.hpp"
#include "rn_node_crypto.h"
#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/HybridObject.hpp>

namespace margelo::nitro::node_crypto {

class HybridDiffieHellman : public HybridHybridDiffieHellmanSpec {
public:
  HybridDiffieHellman(::DiffieHellman *dh)
      : HybridObject("HybridDiffieHellman"), HybridHybridDiffieHellmanSpec(),
        _dh(dh) {}
  virtual ~HybridDiffieHellman() {
    if (_dh) {
      rn_crypto_dh_free(_dh);
      _dh = nullptr;
    }
  }

  std::shared_ptr<ArrayBuffer> generateKeys() override;
  std::shared_ptr<ArrayBuffer>
  computeSecret(const std::shared_ptr<ArrayBuffer> &otherPublicKey) override;
  std::shared_ptr<ArrayBuffer> getPrime() override;
  std::shared_ptr<ArrayBuffer> getGenerator() override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;
  void setPublicKey(const std::shared_ptr<ArrayBuffer> &key) override;
  void setPrivateKey(const std::shared_ptr<ArrayBuffer> &key) override;

private:
  ::DiffieHellman *_dh;
};

class HybridCipher : public HybridHybridCipherSpec {
public:
  HybridCipher(::CipherContext *ctx)
      : HybridObject("HybridCipher"), HybridHybridCipherSpec(), _ctx(ctx) {}
  virtual ~HybridCipher() {
    if (_ctx) {
      rn_crypto_cipher_free(_ctx);
      _ctx = nullptr;
    }
  }

  std::shared_ptr<ArrayBuffer>
  update(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer> final() override;
  void setAutoPadding(bool auto_padding) override;
  void setAAD(const std::shared_ptr<ArrayBuffer> &aad) override;
  std::shared_ptr<ArrayBuffer> getAuthTag() override;

private:
  ::CipherContext *_ctx;
};

class HybridDecipher : public HybridHybridDecipherSpec {
public:
  HybridDecipher(::CipherContext *ctx)
      : HybridObject("HybridDecipher"), HybridHybridDecipherSpec(), _ctx(ctx) {}
  virtual ~HybridDecipher() {
    if (_ctx) {
      rn_crypto_cipher_free(_ctx);
      _ctx = nullptr;
    }
  }

  std::shared_ptr<ArrayBuffer>
  update(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer> final() override;
  void setAutoPadding(bool auto_padding) override;
  void setAAD(const std::shared_ptr<ArrayBuffer> &aad) override;
  void setAuthTag(const std::shared_ptr<ArrayBuffer> &tag) override;

private:
  ::CipherContext *_ctx;
};

// ==================== Sign / Verify ====================

class HybridSign : public HybridHybridSignSpec {
public:
  HybridSign(::SignContext *ctx)
      : HybridObject("HybridSign"), HybridHybridSignSpec(), _ctx(ctx) {}
  virtual ~HybridSign() {
    if (_ctx) {
      rn_crypto_sign_free(_ctx);
      _ctx = nullptr;
    }
  }

  void update(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sign(const std::shared_ptr<ArrayBuffer> &privateKeyPem) override;

private:
  ::SignContext *_ctx;
};

class HybridVerify : public HybridHybridVerifySpec {
public:
  HybridVerify(::VerifyContext *ctx)
      : HybridObject("HybridVerify"), HybridHybridVerifySpec(), _ctx(ctx) {}
  virtual ~HybridVerify() {
    if (_ctx) {
      rn_crypto_verify_free(_ctx);
      _ctx = nullptr;
    }
  }

  void update(const std::shared_ptr<ArrayBuffer> &data) override;
  bool verify(const std::shared_ptr<ArrayBuffer> &publicKeyPem,
              const std::shared_ptr<ArrayBuffer> &signature) override;

private:
  ::VerifyContext *_ctx;
};

// ==================== HMAC ====================

class HybridHmac : public HybridHybridHmacSpec {
public:
  HybridHmac(::HmacContext *ctx)
      : HybridObject("HybridHmac"), HybridHybridHmacSpec(), _ctx(ctx) {}
  virtual ~HybridHmac() {
    if (_ctx) {
      rn_crypto_hmac_free(_ctx);
      _ctx = nullptr;
    }
  }

  void update(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer> digest() override;

private:
  ::HmacContext *_ctx;
};

// ==================== HybridNodeCrypto ====================
class HybridNodeCrypto : public HybridNitroNodeCryptoSpec {
public:
  HybridNodeCrypto() : HybridObject(TAG), HybridNitroNodeCryptoSpec() {}

  // Random
  std::shared_ptr<ArrayBuffer> randomBytes(double size) override;

  // Hash
  std::shared_ptr<ArrayBuffer>
  sha1(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sha256(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sha512(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  md5(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sha384(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sha3_256(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sha3_384(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  sha3_512(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<ArrayBuffer>
  cshake128(const std::shared_ptr<ArrayBuffer> &data,
            const std::shared_ptr<ArrayBuffer> &customization,
            double outputLen) override;
  std::shared_ptr<ArrayBuffer>
  cshake256(const std::shared_ptr<ArrayBuffer> &data,
            const std::shared_ptr<ArrayBuffer> &customization,
            double outputLen) override;

  // HMAC
  std::shared_ptr<HybridHybridHmacSpec>
  createHmac(const std::string &algorithm,
             const std::shared_ptr<ArrayBuffer> &key) override;

  // PBKDF2
  std::shared_ptr<ArrayBuffer>
  pbkdf2Sha256(const std::shared_ptr<ArrayBuffer> &password,
               const std::shared_ptr<ArrayBuffer> &salt, double iterations,
               double keylen) override;

  // Prime generation
  std::shared_ptr<ArrayBuffer> generatePrimeSync(double bits) override;
  bool checkPrimeSync(const std::shared_ptr<ArrayBuffer> &candidate) override;
  std::shared_ptr<HybridHybridDiffieHellmanSpec>
  createDiffieHellmanWithPrimeLength(double primeBits,
                                     double generator) override;

  // Diffie-Hellman
  std::shared_ptr<HybridHybridDiffieHellmanSpec>
  createDiffieHellman(const std::shared_ptr<ArrayBuffer> &prime,
                      const std::shared_ptr<ArrayBuffer> &generator) override;

  // Cipher / Decipher
  std::shared_ptr<HybridHybridCipherSpec>
  createCipheriv(const std::string &algorithm,
                 const std::shared_ptr<ArrayBuffer> &key,
                 const std::shared_ptr<ArrayBuffer> &iv) override;
  std::shared_ptr<HybridHybridDecipherSpec>
  createDecipheriv(const std::string &algorithm,
                   const std::shared_ptr<ArrayBuffer> &key,
                   const std::shared_ptr<ArrayBuffer> &iv) override;

  std::shared_ptr<ArrayBuffer>
  certExportChallenge(const std::shared_ptr<ArrayBuffer> &spkac) override;
  std::shared_ptr<ArrayBuffer>
  certExportPublicKey(const std::shared_ptr<ArrayBuffer> &spkac) override;
  bool certVerifySpkac(const std::shared_ptr<ArrayBuffer> &spkac) override;

  std::shared_ptr<HybridHybridSignSpec>
  createSign(const std::string &algorithm) override;
  std::shared_ptr<HybridHybridVerifySpec>
  createVerify(const std::string &algorithm) override;

  std::shared_ptr<HybridHybridX509CertificateSpec>
  x509Parse(const std::shared_ptr<ArrayBuffer> &data) override;

  std::shared_ptr<HybridHybridECDHSpec>
  createECDH(const std::string &curveName) override;

  std::shared_ptr<HybridHybridKeyObjectSpec>
  createKeyObjectSecret(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<HybridHybridKeyObjectSpec>
  createKeyObjectPublic(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<HybridHybridKeyObjectSpec>
  createKeyObjectPrivate(const std::shared_ptr<ArrayBuffer> &data) override;
  std::shared_ptr<HybridHybridKeyObjectSpec>
  createKeyObjectFromRaw(const std::shared_ptr<ArrayBuffer> &data,
                         double algorithm, bool is_public) override;

  KeyPair generateKeyPairRSA(double modulusBits,
                             double publicExponent) override;
  KeyPair generateKeyPairEC(const std::string &curve) override;
  std::shared_ptr<HybridHybridKeyObjectSpec>
  generateKeySecret(double length) override;
  KeyPair generateKeyPairEd25519() override;
  KeyPair generateKeyPairX25519() override;
  KeyPair generateKeyPairX448() override;

  std::shared_ptr<ArrayBuffer>
  publicEncrypt(const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
                const std::shared_ptr<ArrayBuffer> &buffer,
                double padding) override;
  std::shared_ptr<ArrayBuffer>
  privateDecrypt(const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
                 const std::shared_ptr<ArrayBuffer> &buffer,
                 double padding) override;
  std::shared_ptr<ArrayBuffer>
  privateEncrypt(const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
                 const std::shared_ptr<ArrayBuffer> &buffer,
                 double padding) override;
  std::shared_ptr<ArrayBuffer>
  publicDecrypt(const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
                const std::shared_ptr<ArrayBuffer> &buffer,
                double padding) override;

  std::shared_ptr<ArrayBuffer>
  scrypt(const std::shared_ptr<ArrayBuffer> &password,
         const std::shared_ptr<ArrayBuffer> &salt, double n, double r, double p,
         double len) override;

  std::shared_ptr<ArrayBuffer>
  argon2(const std::shared_ptr<ArrayBuffer> &password,
         const std::shared_ptr<ArrayBuffer> &salt, double iterations,
         double memoryLimit, double parallelism, double hashLength, double type,
         double version) override;

  // Ed448 Key Generation
  KeyPair generateKeyPairEd448() override;

  // DSA Key Generation
  KeyPair generateKeyPairDSA(double L, double N) override;

  // ML-DSA (FIPS 204)
  MLDSAKeyPairResult mldsaKeygen(double level) override;
  std::shared_ptr<ArrayBuffer>
  mldsaSign(double level, const std::shared_ptr<ArrayBuffer> &secretKey,
            const std::shared_ptr<ArrayBuffer> &data) override;
  bool mldsaVerify(double level, const std::shared_ptr<ArrayBuffer> &publicKey,
                   const std::shared_ptr<ArrayBuffer> &data,
                   const std::shared_ptr<ArrayBuffer> &signature) override;
  double mldsaSigLen(double level) override;
  double mldsaPkLen(double level) override;
  double mldsaSkLen(double level) override;

  // ML-KEM (FIPS 203)
  MLKEMOneshotResult mlkemOneshot(double level) override;

  // AEAD (AES-GCM, ChaCha20-Poly1305)
  std::shared_ptr<ArrayBuffer>
  aeadEncrypt(const std::string &algorithm,
              const std::shared_ptr<ArrayBuffer> &key,
              const std::shared_ptr<ArrayBuffer> &nonce,
              const std::shared_ptr<ArrayBuffer> &plaintext,
              const std::shared_ptr<ArrayBuffer> &aad) override;
  std::shared_ptr<ArrayBuffer>
  aeadDecrypt(const std::string &algorithm,
              const std::shared_ptr<ArrayBuffer> &key,
              const std::shared_ptr<ArrayBuffer> &nonce,
              const std::shared_ptr<ArrayBuffer> &ciphertext,
              const std::shared_ptr<ArrayBuffer> &aad) override;

  // AES-KW
  std::shared_ptr<ArrayBuffer>
  aesKwWrap(const std::shared_ptr<ArrayBuffer> &kek,
            const std::shared_ptr<ArrayBuffer> &key) override;
  std::shared_ptr<ArrayBuffer>
  aesKwUnwrap(const std::shared_ptr<ArrayBuffer> &kek,
              const std::shared_ptr<ArrayBuffer> &wrapped) override;

  // DH KeyObject Shared Secret
  std::shared_ptr<ArrayBuffer> dhComputeSecretFromKeys(
      const std::shared_ptr<HybridHybridKeyObjectSpec> &privateKey,
      const std::shared_ptr<HybridHybridKeyObjectSpec> &publicKey) override;

  // DH KeyObject Factory
  std::shared_ptr<HybridHybridKeyObjectSpec> createKeyObjectDhPrivate(
      const std::shared_ptr<ArrayBuffer> &prime,
      const std::shared_ptr<ArrayBuffer> &generator,
      const std::shared_ptr<ArrayBuffer> &privateValue) override;
  std::shared_ptr<HybridHybridKeyObjectSpec> createKeyObjectDhPublic(
      const std::shared_ptr<ArrayBuffer> &prime,
      const std::shared_ptr<ArrayBuffer> &generator,
      const std::shared_ptr<ArrayBuffer> &publicValue) override;

  // ML-KEM (FIPS 203) - Complete API
  MLKEMKeyPairResult mlkemKeygen(double level) override;
  MLKEMOneshotResult mlkemEncapsulate(
      double level,
      const std::shared_ptr<ArrayBuffer> &encapsulationKey) override;
  std::shared_ptr<ArrayBuffer>
  mlkemDecapsulate(double level,
                   const std::shared_ptr<ArrayBuffer> &decapsulationKey,
                   const std::shared_ptr<ArrayBuffer> &ciphertext) override;
  double mlkemEkLen(double level) override;
  double mlkemDkLen(double level) override;
  double mlkemCtLen(double level) override;
  double mlkemSsLen(double level) override;
};

// ==================== HybridKeyObject ====================

class HybridKeyObject : public HybridHybridKeyObjectSpec {
public:
  HybridKeyObject(::KeyObject *key)
      : HybridObject("HybridKeyObject"), HybridHybridKeyObjectSpec(),
        _key(key) {}
  virtual ~HybridKeyObject() {
    if (_key) {
      rn_crypto_key_object_free(_key);
      _key = nullptr;
    }
  }

  double getType() override;
  double getAsymmetricKeyType() override;
  std::shared_ptr<ArrayBuffer> extractData() override;
  std::shared_ptr<ArrayBuffer> exportKey(double format) override;

  // DH accessors
  std::shared_ptr<ArrayBuffer> getDhPrime() override;
  std::shared_ptr<ArrayBuffer> getDhGenerator() override;
  bool isDhKey() override;

  // RSA key details
  double getRsaModulusBits() override;
  std::shared_ptr<ArrayBuffer> getRsaPublicExponent() override;

  // EC key details
  std::string getEcCurveName() override;

  // Helper to get native key for asymmetric operations
  ::KeyObject *getNativeKey() const { return _key; }

private:
  ::KeyObject *_key;
};

// ==================== HybridX509Certificate ====================

class HybridX509Certificate : public HybridHybridX509CertificateSpec {
public:
  HybridX509Certificate(::X509Context *ctx)
      : HybridObject("HybridX509Certificate"),
        HybridHybridX509CertificateSpec(), _ctx(ctx) {}
  virtual ~HybridX509Certificate() {
    if (_ctx) {
      rn_crypto_x509_free(_ctx);
      _ctx = nullptr;
    }
  }

  std::string getFingerprint(const std::string &algorithm) override;
  std::string getIssuer() override;
  std::string getSubject() override;
  std::string getSerialNumber() override;
  std::string getValidFrom() override;
  std::string getValidTo() override;
  std::shared_ptr<ArrayBuffer> getRaw() override;
  std::string toPem() override;

  // New properties
  bool isCa() override;
  std::string getSubjectAltName() override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::string getKeyUsage() override;
  std::string getExtKeyUsage() override;
  std::string getInfoAccess() override;

  // Verification methods
  std::string checkEmail(const std::string &email, bool checkSubject) override;
  std::string checkHost(const std::string &host, bool wildcards) override;
  std::string checkIP(const std::string &ip) override;
  bool verify(const std::shared_ptr<ArrayBuffer> &publicKey) override;
  bool checkIssued(const std::shared_ptr<HybridHybridX509CertificateSpec>
                       &otherCert) override;
  bool checkPrivateKey(const std::shared_ptr<ArrayBuffer> &privateKey) override;

  // Helper to get native context for checkIssued
  ::X509Context *getNativeContext() const { return _ctx; }

private:
  ::X509Context *_ctx;
};

// ==================== HybridECDH ====================

class HybridECDH : public HybridHybridECDHSpec {
public:
  HybridECDH(::ECDH *ctx)
      : HybridObject("HybridECDH"), HybridHybridECDHSpec(), _ctx(ctx) {}
  virtual ~HybridECDH() {
    if (_ctx) {
      rn_crypto_ecdh_free(_ctx);
      _ctx = nullptr;
    }
  }

  std::shared_ptr<ArrayBuffer> generateKeys() override;
  std::shared_ptr<ArrayBuffer>
  computeSecret(const std::shared_ptr<ArrayBuffer> &otherPublicKey) override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;
  std::shared_ptr<ArrayBuffer> getPublicKey(bool compressed) override;
  bool setPrivateKey(const std::shared_ptr<ArrayBuffer> &key) override;
  bool setPublicKey(const std::shared_ptr<ArrayBuffer> &key) override;

private:
  ::ECDH *_ctx;
};

} // namespace margelo::nitro::node_crypto
