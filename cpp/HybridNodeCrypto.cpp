#include "HybridNodeCrypto.hpp"
#include <cstdio>
#include <iostream>
#include <vector>

extern "C" {
#include "rn_node_crypto.h"
}

namespace margelo::nitro::node_crypto {

// ==================== HybridDiffieHellman ====================

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::generateKeys() {
  size_t len = rn_crypto_dh_generate_keys(_dh, nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);

  std::vector<uint8_t> buffer(len);
  rn_crypto_dh_generate_keys(_dh, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::computeSecret(
    const std::shared_ptr<ArrayBuffer> &otherPublicKey) {
  if (!otherPublicKey || otherPublicKey->size() == 0)
    return ArrayBuffer::allocate(0);

  size_t len = rn_crypto_dh_compute_secret(_dh, otherPublicKey->data(),
                                           otherPublicKey->size(), nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);

  std::vector<uint8_t> buffer(len);
  rn_crypto_dh_compute_secret(_dh, otherPublicKey->data(),
                              otherPublicKey->size(), buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPrime() {
  size_t len = rn_crypto_dh_get_prime(_dh, nullptr);
  std::vector<uint8_t> buffer(len);
  rn_crypto_dh_get_prime(_dh, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getGenerator() {
  size_t len = rn_crypto_dh_get_generator(_dh, nullptr);
  std::vector<uint8_t> buffer(len);
  rn_crypto_dh_get_generator(_dh, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPublicKey() {
  size_t len = rn_crypto_dh_get_public_key(_dh, nullptr);
  if (len == 0)
    return nullptr;

  std::vector<uint8_t> buffer(len);
  rn_crypto_dh_get_public_key(_dh, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPrivateKey() {
  size_t len = rn_crypto_dh_get_private_key(_dh, nullptr);
  if (len == 0)
    return nullptr;

  std::vector<uint8_t> buffer(len);
  rn_crypto_dh_get_private_key(_dh, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

void HybridDiffieHellman::setPublicKey(
    const std::shared_ptr<ArrayBuffer> &key) {
  if (key && key->size() > 0) {
    rn_crypto_dh_set_public_key(_dh, key->data(), key->size());
  }
}

void HybridDiffieHellman::setPrivateKey(
    const std::shared_ptr<ArrayBuffer> &key) {
  if (key && key->size() > 0) {
    rn_crypto_dh_set_private_key(_dh, key->data(), key->size());
  }
}

// ==================== HybridCipher ====================

std::shared_ptr<ArrayBuffer>
HybridCipher::update(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data || data->size() == 0)
    return ArrayBuffer::allocate(0);

  // For update, output size can be at most input size + block size (buffered)
  // Or exactly input size for CTR.
  // Rust implementation returns exact bytes written. C API will need a buffer.
  // For safety, allocate input size + 32 bytes (block size margin).
  std::vector<uint8_t> buffer(data->size() + 32);
  size_t written =
      rn_crypto_cipher_update(_ctx, data->data(), data->size(), buffer.data());
  return ArrayBuffer::copy(buffer.data(), written);
}

std::shared_ptr<ArrayBuffer> HybridCipher::final() {
  // Finalize handles padding (up to one block size).
  std::vector<uint8_t> buffer(32); // Max block size usually 16, 32 safe
  size_t written = rn_crypto_cipher_final(_ctx, buffer.data());
  return ArrayBuffer::copy(buffer.data(), written);
}

void HybridCipher::setAutoPadding(bool auto_padding) {
  rn_crypto_cipher_set_auto_padding(_ctx, auto_padding);
}

void HybridCipher::setAAD(const std::shared_ptr<ArrayBuffer> &aad) {
  if (_ctx && aad && aad->size() > 0) {
    rn_crypto_cipher_set_aad(_ctx, aad->data(), aad->size());
  }
}

std::shared_ptr<ArrayBuffer> HybridCipher::getAuthTag() {
  if (!_ctx)
    return ArrayBuffer::allocate(0);

  // First call with NULL to get length
  int32_t len = rn_crypto_cipher_get_auth_tag(_ctx, nullptr, 0);
  if (len <= 0)
    return ArrayBuffer::allocate(0);

  std::vector<uint8_t> buffer(len);
  int32_t res =
      rn_crypto_cipher_get_auth_tag(_ctx, buffer.data(), buffer.size());
  if (res <= 0)
    return ArrayBuffer::allocate(0);

  return ArrayBuffer::copy(buffer.data(), res);
}

// ==================== HybridDecipher ====================

std::shared_ptr<ArrayBuffer>
HybridDecipher::update(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data || data->size() == 0)
    return ArrayBuffer::allocate(0);

  std::vector<uint8_t> buffer(data->size() + 32);
  size_t written =
      rn_crypto_cipher_update(_ctx, data->data(), data->size(), buffer.data());
  return ArrayBuffer::copy(buffer.data(), written);
}

std::shared_ptr<ArrayBuffer> HybridDecipher::final() {
  std::vector<uint8_t> buffer(32);
  size_t written = rn_crypto_cipher_final(_ctx, buffer.data());
  return ArrayBuffer::copy(buffer.data(), written);
}

void HybridDecipher::setAutoPadding(bool auto_padding) {
  rn_crypto_cipher_set_auto_padding(_ctx, auto_padding);
}

void HybridDecipher::setAAD(const std::shared_ptr<ArrayBuffer> &aad) {
  if (_ctx && aad && aad->size() > 0) {
    rn_crypto_cipher_set_aad(_ctx, aad->data(), aad->size());
  }
}

void HybridDecipher::setAuthTag(const std::shared_ptr<ArrayBuffer> &tag) {
  if (_ctx && tag && tag->size() > 0) {
    rn_crypto_cipher_set_auth_tag(_ctx, tag->data(), tag->size());
  }
}

// ==================== HybridNodeCrypto ====================

// ... (Previous methods remain unchanged) ...
std::shared_ptr<ArrayBuffer> HybridNodeCrypto::randomBytes(double size) {
  size_t len = static_cast<size_t>(size);
  std::vector<uint8_t> buffer(len);
  rn_crypto_random_bytes(buffer.data(), len);
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha1(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[20];
  rn_crypto_sha1(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 20);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha256(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[32];
  rn_crypto_sha256(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 32);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha512(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[64];
  rn_crypto_sha512(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 64);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::md5(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[16];
  rn_crypto_md5(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 16);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha384(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[48];
  rn_crypto_sha384(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 48);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha3_256(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[32];
  rn_crypto_sha3_256(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 32);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha3_384(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[48];
  rn_crypto_sha3_384(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 48);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::sha3_512(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return ArrayBuffer::allocate(0);
  uint8_t hash[64];
  rn_crypto_sha3_512(data->data(), data->size(), hash);
  return ArrayBuffer::copy(hash, 64);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::cshake128(const std::shared_ptr<ArrayBuffer> &data,
                            const std::shared_ptr<ArrayBuffer> &customization,
                            double outputLen) {
  if (!data)
    return ArrayBuffer::allocate(0);
  size_t outLen = static_cast<size_t>(outputLen);
  std::vector<uint8_t> hash(outLen);
  const uint8_t *customData = customization ? customization->data() : nullptr;
  size_t customLen = customization ? customization->size() : 0;
  rn_crypto_cshake128(data->data(), data->size(), customData, customLen,
                      hash.data(), outLen);
  return ArrayBuffer::copy(hash.data(), hash.size());
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::cshake256(const std::shared_ptr<ArrayBuffer> &data,
                            const std::shared_ptr<ArrayBuffer> &customization,
                            double outputLen) {
  if (!data)
    return ArrayBuffer::allocate(0);
  size_t outLen = static_cast<size_t>(outputLen);
  std::vector<uint8_t> hash(outLen);
  const uint8_t *customData = customization ? customization->data() : nullptr;
  size_t customLen = customization ? customization->size() : 0;
  rn_crypto_cshake256(data->data(), data->size(), customData, customLen,
                      hash.data(), outLen);
  return ArrayBuffer::copy(hash.data(), hash.size());
}

// ==================== HybridHmac ====================

void HybridHmac::update(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data || data->size() == 0 || !_ctx)
    return;
  rn_crypto_hmac_update(_ctx, data->data(), data->size());
}

std::shared_ptr<ArrayBuffer> HybridHmac::digest() {
  if (!_ctx)
    return ArrayBuffer::allocate(0);

  // Get output length
  // The C API rn_crypto_hmac_digest returns the size written.
  // We need to know the size beforehand or use a large buffer?
  // Or generic HMAC context knows its size?
  // We added `rn_crypto_hmac_output_len` in Rust but it takes algorithm name.
  // HmacContext in Rust knows its size.
  // `rn_crypto_hmac_digest` in Rust currently handles the allocation? No, it
  // takes `out` pointer. "out_slice = slice::from_raw_parts_mut(out,
  // result.len());" in Rust. If we pass a buffer that is too small, we might
  // have issues? Rust implementation: "let result = hmac_ctx.finalize(); let
  // out_slice = ...; out_slice.copy_from_slice(&result);" If `out` buffer is
  // small, this will panic in Rust or corrupt memory if we didn't check size.
  // The Rust function returns `result.len()`.
  //
  // Option 1: Provide a buffer large enough for MAX hash (SHA512 = 64 bytes).
  // SHA3-512 is also 64 bytes.
  // So a 64-byte buffer is sufficient for all supported algorithms.

  std::vector<uint8_t> buffer(64);
  size_t len = rn_crypto_hmac_digest(_ctx, buffer.data());

  // CRITICAL: rn_crypto_hmac_digest() consumes the context (Box::from_raw in
  // Rust) So we must set _ctx to nullptr to prevent double-free in destructor
  _ctx = nullptr;

  if (len == 0) {
    return ArrayBuffer::allocate(0);
  }

  return ArrayBuffer::copy(buffer.data(), len);
}

// ==================== HybridNodeCrypto HMAC Factory ====================

std::shared_ptr<HybridHybridHmacSpec>
HybridNodeCrypto::createHmac(const std::string &algorithm,
                             const std::shared_ptr<ArrayBuffer> &key) {
  if (!key)
    return nullptr;

  ::HmacContext *ctx = rn_crypto_hmac_create(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size());

  if (!ctx)
    return nullptr;

  return std::make_shared<HybridHmac>(ctx);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::pbkdf2Sha256(const std::shared_ptr<ArrayBuffer> &password,
                               const std::shared_ptr<ArrayBuffer> &salt,
                               double iterations, double keylen) {
  if (!password || !salt)
    return ArrayBuffer::allocate(0);
  size_t len = static_cast<size_t>(keylen);
  std::vector<uint8_t> key(len);
  rn_crypto_pbkdf2_sha256(password->data(), password->size(), salt->data(),
                          salt->size(), static_cast<uint32_t>(iterations),
                          key.data(), len);
  return ArrayBuffer::copy(key.data(), key.size());
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::generatePrimeSync(double bits) {
  size_t bit_count = static_cast<size_t>(bits);
  size_t len = rn_crypto_generate_prime(bit_count, nullptr);
  std::vector<uint8_t> buffer(len);
  rn_crypto_generate_prime(bit_count, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

bool HybridNodeCrypto::checkPrimeSync(
    const std::shared_ptr<ArrayBuffer> &candidate) {
  if (!candidate || candidate->size() == 0)
    return false;
  return rn_crypto_check_prime(candidate->data(), candidate->size());
}

std::shared_ptr<HybridHybridDiffieHellmanSpec>
HybridNodeCrypto::createDiffieHellmanWithPrimeLength(double primeBits,
                                                     double generator) {
  ::DiffieHellman *dh = rn_crypto_dh_new_with_prime_length(
      static_cast<size_t>(primeBits), static_cast<size_t>(generator));
  if (!dh)
    return nullptr;
  return std::make_shared<HybridDiffieHellman>(dh);
}

std::shared_ptr<HybridHybridDiffieHellmanSpec>
HybridNodeCrypto::createDiffieHellman(
    const std::shared_ptr<ArrayBuffer> &prime,
    const std::shared_ptr<ArrayBuffer> &generator) {
  if (!prime || !generator)
    return nullptr;

  ::DiffieHellman *dh = rn_crypto_dh_new(prime->data(), prime->size(),
                                         generator->data(), generator->size());

  return std::make_shared<HybridDiffieHellman>(dh);
}

std::shared_ptr<HybridHybridCipherSpec>
HybridNodeCrypto::createCipheriv(const std::string &algorithm,
                                 const std::shared_ptr<ArrayBuffer> &key,
                                 const std::shared_ptr<ArrayBuffer> &iv) {
  if (!key || !iv)
    return nullptr;

  ::CipherContext *ctx = rn_crypto_cipher_create(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size(), iv->data(), iv->size(),
      false); // is_decipher = false
  if (!ctx)
    return nullptr; // Handle bad algo

  return std::make_shared<HybridCipher>(ctx);
}

std::shared_ptr<HybridHybridDecipherSpec>
HybridNodeCrypto::createDecipheriv(const std::string &algorithm,
                                   const std::shared_ptr<ArrayBuffer> &key,
                                   const std::shared_ptr<ArrayBuffer> &iv) {
  if (!key || !iv)
    return nullptr;

  ::CipherContext *ctx = rn_crypto_cipher_create(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size(), iv->data(), iv->size(),
      true); // is_decipher = true
  if (!ctx)
    return nullptr;

  return std::make_shared<HybridDecipher>(ctx);
}

// ==================== HybridSign ====================

void HybridSign::update(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data || data->size() == 0 || !_ctx)
    return;
  rn_crypto_sign_update(_ctx, data->data(), data->size());
}

std::shared_ptr<ArrayBuffer>
HybridSign::sign(const std::shared_ptr<ArrayBuffer> &privateKeyPem) {
  if (!_ctx || !privateKeyPem)
    return ArrayBuffer::allocate(0);

  // First call with null to get size
  size_t sig_len = rn_crypto_sign_sign(_ctx, privateKeyPem->data(),
                                       privateKeyPem->size(), nullptr);
  if (sig_len == 0)
    return ArrayBuffer::allocate(0);

  std::vector<uint8_t> buffer(sig_len);
  rn_crypto_sign_sign(_ctx, privateKeyPem->data(), privateKeyPem->size(),
                      buffer.data());

  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

// ==================== HybridVerify ====================

void HybridVerify::update(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data || data->size() == 0 || !_ctx)
    return;
  rn_crypto_verify_update(_ctx, data->data(), data->size());
}

bool HybridVerify::verify(const std::shared_ptr<ArrayBuffer> &publicKeyPem,
                          const std::shared_ptr<ArrayBuffer> &signature) {
  if (!_ctx || !publicKeyPem || !signature)
    return false;
  return rn_crypto_verify_verify(_ctx, publicKeyPem->data(),
                                 publicKeyPem->size(), signature->data(),
                                 signature->size());
}

// ==================== Factory Methods ====================

std::shared_ptr<HybridHybridSignSpec>
HybridNodeCrypto::createSign(const std::string &algorithm) {
  ::SignContext *ctx = rn_crypto_sign_create(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length());
  if (!ctx)
    return nullptr;
  return std::make_shared<HybridSign>(ctx);
}

std::shared_ptr<HybridHybridVerifySpec>
HybridNodeCrypto::createVerify(const std::string &algorithm) {
  ::VerifyContext *ctx = rn_crypto_verify_create(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length());
  if (!ctx)
    return nullptr;
  return std::make_shared<HybridVerify>(ctx);
}

// ==================== SPKAC Certificate Methods ====================

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::certExportChallenge(
    const std::shared_ptr<ArrayBuffer> &spkac) {
  if (!spkac)
    return ArrayBuffer::allocate(0);
  size_t len =
      rn_crypto_cert_export_challenge(spkac->data(), spkac->size(), nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_cert_export_challenge(spkac->data(), spkac->size(), buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::certExportPublicKey(
    const std::shared_ptr<ArrayBuffer> &spkac) {
  if (!spkac)
    return ArrayBuffer::allocate(0);
  size_t len =
      rn_crypto_cert_export_public_key(spkac->data(), spkac->size(), nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_cert_export_public_key(spkac->data(), spkac->size(), buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

bool HybridNodeCrypto::certVerifySpkac(
    const std::shared_ptr<ArrayBuffer> &spkac) {
  if (!spkac)
    return false;
  return rn_crypto_cert_verify_spkac(spkac->data(), spkac->size());
}

// ==================== HybridX509Certificate ====================

std::shared_ptr<HybridHybridX509CertificateSpec>
HybridNodeCrypto::x509Parse(const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return nullptr;
  ::X509Context *ctx = rn_crypto_x509_parse(data->data(), data->size());
  if (!ctx)
    return nullptr;
  return std::make_shared<HybridX509Certificate>(ctx);
}

std::string
HybridX509Certificate::getFingerprint(const std::string &algorithm) {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_fingerprint(
      _ctx, reinterpret_cast<const uint8_t *>(algorithm.c_str()),
      algorithm.length(), nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_fingerprint(
      _ctx, reinterpret_cast<const uint8_t *>(algorithm.c_str()),
      algorithm.length(), reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getIssuer() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_issuer(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_issuer(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getSubject() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_subject(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_subject(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getSerialNumber() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_serial(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_serial(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getValidFrom() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_valid_from(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_valid_from(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getValidTo() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_valid_to(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_valid_to(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::shared_ptr<ArrayBuffer> HybridX509Certificate::getRaw() {
  if (!_ctx)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_x509_raw(_ctx, nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_x509_raw(_ctx, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::string HybridX509Certificate::toPem() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_to_pem(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_to_pem(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

// ==================== New X509 Properties ====================

bool HybridX509Certificate::isCa() {
  if (!_ctx)
    return false;
  return rn_crypto_x509_is_ca(_ctx);
}

std::string HybridX509Certificate::getSubjectAltName() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_subject_alt_name(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_subject_alt_name(_ctx,
                                  reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::shared_ptr<ArrayBuffer> HybridX509Certificate::getPublicKey() {
  if (!_ctx)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_x509_public_key(_ctx, nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_x509_public_key(_ctx, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::string HybridX509Certificate::getKeyUsage() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_key_usage(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_key_usage(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getExtKeyUsage() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_ext_key_usage(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_ext_key_usage(_ctx,
                               reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::getInfoAccess() {
  if (!_ctx)
    return "";
  size_t len = rn_crypto_x509_info_access(_ctx, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_info_access(_ctx, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

// ==================== X509 Verification Methods ====================

std::string HybridX509Certificate::checkEmail(const std::string &email,
                                              bool checkSubject) {
  if (!_ctx || email.empty())
    return "";
  size_t len = rn_crypto_x509_check_email(
      _ctx, reinterpret_cast<const uint8_t *>(email.c_str()), email.length(),
      checkSubject, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_check_email(
      _ctx, reinterpret_cast<const uint8_t *>(email.c_str()), email.length(),
      checkSubject, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::checkHost(const std::string &host,
                                             bool wildcards) {
  if (!_ctx || host.empty())
    return "";
  size_t len = rn_crypto_x509_check_host(
      _ctx, reinterpret_cast<const uint8_t *>(host.c_str()), host.length(),
      wildcards, nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_check_host(
      _ctx, reinterpret_cast<const uint8_t *>(host.c_str()), host.length(),
      wildcards, reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

std::string HybridX509Certificate::checkIP(const std::string &ip) {
  if (!_ctx || ip.empty())
    return "";
  size_t len = rn_crypto_x509_check_ip(
      _ctx, reinterpret_cast<const uint8_t *>(ip.c_str()), ip.length(),
      nullptr);
  if (len == 0)
    return "";
  std::vector<char> buffer(len);
  rn_crypto_x509_check_ip(_ctx, reinterpret_cast<const uint8_t *>(ip.c_str()),
                          ip.length(),
                          reinterpret_cast<uint8_t *>(buffer.data()));
  return std::string(buffer.begin(), buffer.end());
}

bool HybridX509Certificate::verify(
    const std::shared_ptr<ArrayBuffer> &publicKey) {
  if (!_ctx || !publicKey || publicKey->size() == 0)
    return false;
  return rn_crypto_x509_verify(_ctx, publicKey->data(), publicKey->size());
}

bool HybridX509Certificate::checkIssued(
    const std::shared_ptr<HybridHybridX509CertificateSpec> &otherCert) {
  if (!_ctx || !otherCert)
    return false;
  auto other = std::dynamic_pointer_cast<HybridX509Certificate>(otherCert);
  if (!other || !other->getNativeContext())
    return false;
  return rn_crypto_x509_check_issued(_ctx, other->getNativeContext());
}

bool HybridX509Certificate::checkPrivateKey(
    const std::shared_ptr<ArrayBuffer> &privateKey) {
  if (!_ctx || !privateKey || privateKey->size() == 0)
    return false;
  return rn_crypto_x509_check_private_key(_ctx, privateKey->data(),
                                          privateKey->size());
}

// ==================== HybridECDH ====================

std::shared_ptr<HybridHybridECDHSpec>
HybridNodeCrypto::createECDH(const std::string &curveName) {
  ::ECDH *ctx = rn_crypto_ecdh_new(
      reinterpret_cast<const uint8_t *>(curveName.c_str()), curveName.length());
  if (!ctx)
    return nullptr;
  return std::make_shared<HybridECDH>(ctx);
}

// ==================== HybridKeyObject ====================

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::createKeyObjectSecret(
    const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return nullptr;
  ::KeyObject *key =
      rn_crypto_key_object_new_secret(data->data(), data->size());
  if (!key)
    return nullptr;
  return std::make_shared<HybridKeyObject>(key);
}

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::createKeyObjectPublic(
    const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return nullptr;
  ::KeyObject *key =
      rn_crypto_key_object_new_public(data->data(), data->size());
  if (!key)
    return nullptr;
  return std::make_shared<HybridKeyObject>(key);
}

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::createKeyObjectPrivate(
    const std::shared_ptr<ArrayBuffer> &data) {
  if (!data)
    return nullptr;
  ::KeyObject *key =
      rn_crypto_key_object_new_private(data->data(), data->size());
  if (!key)
    return nullptr;
  return std::make_shared<HybridKeyObject>(key);
}

KeyPair HybridNodeCrypto::generateKeyPairRSA(double modulusBits,
                                             double publicExponent) {
  ::KeyObject *pub = nullptr;
  ::KeyObject *priv = nullptr;
  int32_t res =
      rn_crypto_keygen_rsa(static_cast<uint32_t>(modulusBits),
                           static_cast<uint32_t>(publicExponent), &pub, &priv);
  if (res != 0) {
    // Return empty/null objects? Or throw?
    // Nitro doesn't easily support throwing specific JS errors from C++ yet
    // without effort. Let's return nulls or throw runtime_error.
    throw std::runtime_error("RSA Key Generation failed");
  }
  return KeyPair{std::make_shared<HybridKeyObject>(pub),
                 std::make_shared<HybridKeyObject>(priv)};
}

KeyPair HybridNodeCrypto::generateKeyPairEC(const std::string &curve) {
  ::KeyObject *pub = nullptr;
  ::KeyObject *priv = nullptr;
  int32_t res = rn_crypto_keygen_ec(curve.c_str(), &pub, &priv);
  if (res != 0) {
    throw std::runtime_error("EC Key Generation failed");
  }
  return KeyPair{std::make_shared<HybridKeyObject>(pub),
                 std::make_shared<HybridKeyObject>(priv)};
}

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::generateKeySecret(double length) {
  ::KeyObject *key = nullptr;
  int32_t res = rn_crypto_keygen_secret(static_cast<size_t>(length), &key);
  if (res != 0) {
    throw std::runtime_error("Secret Key Generation failed");
  }
  return std::make_shared<HybridKeyObject>(key);
}

KeyPair HybridNodeCrypto::generateKeyPairEd25519() {
  ::KeyObject *pub = nullptr, *priv = nullptr;
  int32_t res = rn_crypto_keygen_ed25519(&pub, &priv);
  if (res != 0) {
    throw std::runtime_error("Ed25519 Key Generation failed");
  }
  return KeyPair{std::make_shared<HybridKeyObject>(pub),
                 std::make_shared<HybridKeyObject>(priv)};
}

KeyPair HybridNodeCrypto::generateKeyPairX25519() {
  ::KeyObject *pub = nullptr, *priv = nullptr;
  int32_t res = rn_crypto_keygen_x25519(&pub, &priv);
  if (res != 0) {
    throw std::runtime_error("X25519 Key Generation failed");
  }
  return KeyPair{std::make_shared<HybridKeyObject>(pub),
                 std::make_shared<HybridKeyObject>(priv)};
}

KeyPair HybridNodeCrypto::generateKeyPairX448() {
  ::KeyObject *pub = nullptr, *priv = nullptr;
  int32_t res = rn_crypto_keygen_x448(&pub, &priv);
  if (res != 0) {
    throw std::runtime_error("X448 Key Generation failed");
  }
  return KeyPair{std::make_shared<HybridKeyObject>(pub),
                 std::make_shared<HybridKeyObject>(priv)};
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::publicEncrypt(
    const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
    const std::shared_ptr<ArrayBuffer> &buffer, double padding) {
  if (!key || !buffer)
    return nullptr;
  auto nativeKey = std::dynamic_pointer_cast<HybridKeyObject>(key);
  if (!nativeKey || !nativeKey->getNativeKey())
    return nullptr;

  // First call to get length or error
  int32_t len = rn_crypto_public_encrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), nullptr, 0);
  if (len < 0) {
    throw std::runtime_error("publicEncrypt failed");
  }

  std::vector<uint8_t> out(len);
  int32_t res = rn_crypto_public_encrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), out.data(), out.size());
  if (res < 0) {
    throw std::runtime_error("publicEncrypt failed");
  }
  return ArrayBuffer::copy(out.data(), out.size());
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::privateDecrypt(
    const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
    const std::shared_ptr<ArrayBuffer> &buffer, double padding) {
  if (!key || !buffer)
    return nullptr;
  auto nativeKey = std::dynamic_pointer_cast<HybridKeyObject>(key);
  if (!nativeKey || !nativeKey->getNativeKey())
    return nullptr;

  int32_t len = rn_crypto_private_decrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), nullptr, 0);
  if (len < 0) {
    throw std::runtime_error("privateDecrypt failed");
  }

  std::vector<uint8_t> out(len);
  int32_t res = rn_crypto_private_decrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), out.data(), out.size());
  if (res < 0) {
    throw std::runtime_error("privateDecrypt failed");
  }
  return ArrayBuffer::copy(out.data(), out.size());
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::privateEncrypt(
    const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
    const std::shared_ptr<ArrayBuffer> &buffer, double padding) {
  if (!key || !buffer)
    return nullptr;
  auto nativeKey = std::dynamic_pointer_cast<HybridKeyObject>(key);
  if (!nativeKey || !nativeKey->getNativeKey())
    return nullptr;

  int32_t len = rn_crypto_private_encrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), nullptr, 0);
  if (len < 0) {
    throw std::runtime_error("privateEncrypt failed");
  }

  std::vector<uint8_t> out(len);
  int32_t res = rn_crypto_private_encrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), out.data(), out.size());
  if (res < 0) {
    throw std::runtime_error("privateEncrypt failed");
  }
  return ArrayBuffer::copy(out.data(), out.size());
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::publicDecrypt(
    const std::shared_ptr<HybridHybridKeyObjectSpec> &key,
    const std::shared_ptr<ArrayBuffer> &buffer, double padding) {
  if (!key || !buffer)
    return nullptr;
  auto nativeKey = std::dynamic_pointer_cast<HybridKeyObject>(key);
  if (!nativeKey || !nativeKey->getNativeKey())
    return nullptr;

  int32_t len = rn_crypto_public_decrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), nullptr, 0);
  if (len < 0) {
    throw std::runtime_error("publicDecrypt failed");
  }

  std::vector<uint8_t> out(len);
  int32_t res = rn_crypto_public_decrypt(
      nativeKey->getNativeKey(), buffer->data(), buffer->size(),
      static_cast<int32_t>(padding), out.data(), out.size());
  if (res < 0) {
    throw std::runtime_error("publicDecrypt failed");
  }
  return ArrayBuffer::copy(out.data(), out.size());
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::scrypt(const std::shared_ptr<ArrayBuffer> &password,
                         const std::shared_ptr<ArrayBuffer> &salt, double n,
                         double r, double p, double len) {
  if (!password || !salt)
    return nullptr;

  std::vector<uint8_t> out(static_cast<size_t>(len));
  int32_t res = rn_crypto_scrypt(
      password->data(), password->size(), salt->data(), salt->size(),
      static_cast<uint32_t>(n), static_cast<uint32_t>(r),
      static_cast<uint32_t>(p), static_cast<size_t>(len), out.data());

  if (res < 0) {
    throw std::runtime_error("scrypt failed");
  }
  return ArrayBuffer::copy(out.data(), out.size());
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::argon2(const std::shared_ptr<ArrayBuffer> &password,
                         const std::shared_ptr<ArrayBuffer> &salt,
                         double iterations, double memoryLimit,
                         double parallelism, double hashLength, double type,
                         double version) {
  if (!password || !salt)
    throw std::runtime_error("argon2: invalid input");

  std::vector<uint8_t> out(static_cast<size_t>(hashLength));
  int32_t res = rn_crypto_argon2(
      password->data(), password->size(), salt->data(), salt->size(),
      static_cast<uint32_t>(iterations), static_cast<uint32_t>(memoryLimit),
      static_cast<uint32_t>(parallelism), static_cast<uint32_t>(hashLength),
      static_cast<int32_t>(type), static_cast<int32_t>(version), out.data());

  if (res < 0) {
    throw std::runtime_error("argon2 failed");
  }
  return ArrayBuffer::copy(out.data(), out.size());
}

// ==================== HybridKeyObject Methods ====================

double HybridKeyObject::getType() {
  if (!_key)
    return -1;
  return static_cast<double>(rn_crypto_key_object_get_type(_key));
}

double HybridKeyObject::getAsymmetricKeyType() {
  if (!_key)
    return -1;
  return static_cast<double>(
      rn_crypto_key_object_get_asymmetric_key_type(_key));
}

std::shared_ptr<ArrayBuffer> HybridKeyObject::extractData() {
  if (!_key)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_key_object_get_data(_key, nullptr);
  std::vector<uint8_t> buffer(len);
  rn_crypto_key_object_get_data(_key, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridKeyObject::exportKey(double format) {
  if (!_key)
    return ArrayBuffer::allocate(0);

  // First call to get size (returns size or -1 on error)
  int32_t len =
      rn_crypto_key_object_export(_key, static_cast<int32_t>(format), nullptr);
  if (len < 0) {
    // Error or empty
    return ArrayBuffer::allocate(0);
  }

  std::vector<uint8_t> buffer(len);
  int32_t res = rn_crypto_key_object_export(_key, static_cast<int32_t>(format),
                                            buffer.data());
  if (res < 0) {
    return ArrayBuffer::allocate(0);
  }
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

// ==================== HybridKeyObject DH/RSA/EC Methods ====================

std::shared_ptr<ArrayBuffer> HybridKeyObject::getDhPrime() {
  if (!_key)
    return ArrayBuffer::allocate(0);
  int32_t len = rn_crypto_key_object_get_dh_prime(_key, nullptr);
  if (len <= 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_key_object_get_dh_prime(_key, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridKeyObject::getDhGenerator() {
  if (!_key)
    return ArrayBuffer::allocate(0);
  int32_t len = rn_crypto_key_object_get_dh_generator(_key, nullptr);
  if (len <= 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_key_object_get_dh_generator(_key, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

bool HybridKeyObject::isDhKey() {
  if (!_key)
    return false;
  return rn_crypto_key_object_is_dh(_key);
}

double HybridKeyObject::getRsaModulusBits() {
  // TODO: Implement when RSA key details API is available in Rust
  return 0;
}

std::shared_ptr<ArrayBuffer> HybridKeyObject::getRsaPublicExponent() {
  // TODO: Implement when RSA key details API is available in Rust
  return ArrayBuffer::allocate(0);
}

std::string HybridKeyObject::getEcCurveName() {
  // TODO: Implement when EC key details API is available in Rust
  return "";
}

// ... existing code ...

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::createKeyObjectFromRaw(
    const std::shared_ptr<ArrayBuffer> &data, double algorithm,
    bool is_public) {
  if (!data)
    return nullptr;
  ::KeyObject *key = rn_crypto_key_object_new_from_raw(
      data->data(), data->size(), static_cast<int32_t>(algorithm), is_public);
  if (!key)
    return nullptr;
  return std::make_shared<HybridKeyObject>(key);
}

std::shared_ptr<ArrayBuffer> HybridECDH::generateKeys() {
  if (!_ctx)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_ecdh_generate_keys(_ctx, nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_ecdh_generate_keys(_ctx, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer>
HybridECDH::computeSecret(const std::shared_ptr<ArrayBuffer> &otherPublicKey) {
  if (!_ctx || !otherPublicKey)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_ecdh_compute_secret(_ctx, otherPublicKey->data(),
                                             otherPublicKey->size(), nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_ecdh_compute_secret(_ctx, otherPublicKey->data(),
                                otherPublicKey->size(), buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPrivateKey() {
  if (!_ctx)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_ecdh_get_private_key(_ctx, nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_ecdh_get_private_key(_ctx, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPublicKey(bool compressed) {
  if (!_ctx)
    return ArrayBuffer::allocate(0);
  size_t len = rn_crypto_ecdh_get_public_key(_ctx, compressed, nullptr);
  if (len == 0)
    return ArrayBuffer::allocate(0);
  std::vector<uint8_t> buffer(len);
  rn_crypto_ecdh_get_public_key(_ctx, compressed, buffer.data());
  return ArrayBuffer::copy(buffer.data(), buffer.size());
}

bool HybridECDH::setPrivateKey(const std::shared_ptr<ArrayBuffer> &key) {
  if (!_ctx || !key)
    return false;
  return rn_crypto_ecdh_set_private_key(_ctx, key->data(), key->size());
}

bool HybridECDH::setPublicKey(const std::shared_ptr<ArrayBuffer> &key) {
  if (!_ctx || !key)
    return false;
  return rn_crypto_ecdh_set_public_key(_ctx, key->data(), key->size());
}

// ==================== Ed448 Key Generation ====================

KeyPair HybridNodeCrypto::generateKeyPairEd448() {
  ::KeyObject *pub = nullptr, *priv = nullptr;
  int32_t res = rn_crypto_keygen_ed448(&pub, &priv);
  if (res != 0) {
    throw std::runtime_error("Ed448 Key Generation failed");
  }
  return KeyPair{std::make_shared<HybridKeyObject>(pub),
                 std::make_shared<HybridKeyObject>(priv)};
}

// ==================== DSA Key Generation ====================

KeyPair HybridNodeCrypto::generateKeyPairDSA(double L, double N) {
  // TODO: Implement DSA key generation when rn_crypto_keygen_dsa is available
  (void)L;
  (void)N;
  throw std::runtime_error("DSA Key Generation not yet implemented");
}

// ==================== ML-DSA (FIPS 204) ====================

MLDSAKeyPairResult HybridNodeCrypto::mldsaKeygen(double level) {
  int32_t lvl = static_cast<int32_t>(level);
  ::MLDSAKeyPair *kp = rn_crypto_mldsa_keygen(lvl);
  if (!kp) {
    throw std::runtime_error("ML-DSA Key Generation failed");
  }

  auto pk = ArrayBuffer::copy(kp->public_key, kp->public_key_len);
  auto sk = ArrayBuffer::copy(kp->secret_key, kp->secret_key_len);
  rn_crypto_mldsa_keypair_free(kp);

  return MLDSAKeyPairResult{pk, sk};
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::mldsaSign(double level,
                            const std::shared_ptr<ArrayBuffer> &secretKey,
                            const std::shared_ptr<ArrayBuffer> &data) {
  if (!secretKey || !data)
    throw std::runtime_error("ML-DSA Sign: invalid input");

  int32_t lvl = static_cast<int32_t>(level);
  size_t sig_len = rn_crypto_mldsa_sig_len(lvl);
  if (sig_len == 0) {
    throw std::runtime_error("ML-DSA Sign: invalid level");
  }

  std::vector<uint8_t> sig(sig_len);
  size_t written =
      rn_crypto_mldsa_sign(lvl, secretKey->data(), secretKey->size(),
                           data->data(), data->size(), sig.data());
  if (written == 0) {
    throw std::runtime_error("ML-DSA Sign failed");
  }

  return ArrayBuffer::copy(sig.data(), written);
}

bool HybridNodeCrypto::mldsaVerify(
    double level, const std::shared_ptr<ArrayBuffer> &publicKey,
    const std::shared_ptr<ArrayBuffer> &data,
    const std::shared_ptr<ArrayBuffer> &signature) {
  if (!publicKey || !data || !signature)
    return false;

  int32_t lvl = static_cast<int32_t>(level);
  return rn_crypto_mldsa_verify(lvl, publicKey->data(), publicKey->size(),
                                data->data(), data->size(), signature->data(),
                                signature->size());
}

double HybridNodeCrypto::mldsaSigLen(double level) {
  return static_cast<double>(
      rn_crypto_mldsa_sig_len(static_cast<int32_t>(level)));
}

double HybridNodeCrypto::mldsaPkLen(double level) {
  return static_cast<double>(
      rn_crypto_mldsa_pk_len(static_cast<int32_t>(level)));
}

double HybridNodeCrypto::mldsaSkLen(double level) {
  return static_cast<double>(
      rn_crypto_mldsa_sk_len(static_cast<int32_t>(level)));
}

// ==================== ML-KEM (FIPS 203) ====================

MLKEMOneshotResult HybridNodeCrypto::mlkemOneshot(double level) {
  int32_t lvl = static_cast<int32_t>(level);

  // Max sizes for ML-KEM-1024
  std::vector<uint8_t> ct(1568); // Max ciphertext size
  std::vector<uint8_t> ss(32);   // Shared secret is always 32 bytes
  size_t ct_len = 0, ss_len = 0;

  int32_t res =
      rn_crypto_mlkem_oneshot(lvl, ct.data(), &ct_len, ss.data(), &ss_len);
  if (res != 0) {
    throw std::runtime_error("ML-KEM oneshot failed");
  }

  return MLKEMOneshotResult{ArrayBuffer::copy(ct.data(), ct_len),
                            ArrayBuffer::copy(ss.data(), ss_len)};
}

// ==================== AEAD (AES-GCM, ChaCha20-Poly1305) ====================

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::aeadEncrypt(const std::string &algorithm,
                              const std::shared_ptr<ArrayBuffer> &key,
                              const std::shared_ptr<ArrayBuffer> &nonce,
                              const std::shared_ptr<ArrayBuffer> &plaintext,
                              const std::shared_ptr<ArrayBuffer> &aad) {
  if (!key || !nonce || !plaintext)
    throw std::runtime_error("AEAD encrypt: invalid input");

  const uint8_t *aadData = aad ? aad->data() : nullptr;
  size_t aadLen = aad ? aad->size() : 0;

  // First call to get output size
  int32_t outLen = rn_crypto_aead_encrypt(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size(), nonce->data(), nonce->size(), plaintext->data(),
      plaintext->size(), aadData, aadLen, nullptr, 0);

  if (outLen < 0) {
    throw std::runtime_error("AEAD encrypt failed");
  }

  std::vector<uint8_t> out(outLen);
  int32_t res = rn_crypto_aead_encrypt(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size(), nonce->data(), nonce->size(), plaintext->data(),
      plaintext->size(), aadData, aadLen, out.data(), out.size());

  if (res < 0) {
    throw std::runtime_error("AEAD encrypt failed");
  }

  return ArrayBuffer::copy(out.data(), res);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::aeadDecrypt(const std::string &algorithm,
                              const std::shared_ptr<ArrayBuffer> &key,
                              const std::shared_ptr<ArrayBuffer> &nonce,
                              const std::shared_ptr<ArrayBuffer> &ciphertext,
                              const std::shared_ptr<ArrayBuffer> &aad) {
  if (!key || !nonce || !ciphertext)
    throw std::runtime_error("AEAD decrypt: invalid input");

  const uint8_t *aadData = aad ? aad->data() : nullptr;
  size_t aadLen = aad ? aad->size() : 0;

  // First call to get output size
  int32_t outLen = rn_crypto_aead_decrypt(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size(), nonce->data(), nonce->size(),
      ciphertext->data(), ciphertext->size(), aadData, aadLen, nullptr, 0);

  if (outLen < 0) {
    throw std::runtime_error("AEAD decrypt failed: authentication error");
  }

  std::vector<uint8_t> out(outLen);
  int32_t res = rn_crypto_aead_decrypt(
      reinterpret_cast<const uint8_t *>(algorithm.c_str()), algorithm.length(),
      key->data(), key->size(), nonce->data(), nonce->size(),
      ciphertext->data(), ciphertext->size(), aadData, aadLen, out.data(),
      out.size());

  if (res < 0) {
    throw std::runtime_error("AEAD decrypt failed: authentication error");
  }

  return ArrayBuffer::copy(out.data(), res);
}

// ==================== AES-KW (RFC 3394) ====================

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::aesKwWrap(const std::shared_ptr<ArrayBuffer> &kek,
                            const std::shared_ptr<ArrayBuffer> &key) {
  if (!kek || !key)
    throw std::runtime_error("AES-KW wrap: invalid input");

  // First call to get output size
  int32_t outLen = rn_crypto_aes_kw_wrap(kek->data(), kek->size(), key->data(),
                                         key->size(), nullptr);
  if (outLen < 0) {
    throw std::runtime_error("AES-KW wrap failed");
  }

  std::vector<uint8_t> out(outLen);
  int32_t res = rn_crypto_aes_kw_wrap(kek->data(), kek->size(), key->data(),
                                      key->size(), out.data());
  if (res < 0) {
    throw std::runtime_error("AES-KW wrap failed");
  }

  return ArrayBuffer::copy(out.data(), res);
}

std::shared_ptr<ArrayBuffer>
HybridNodeCrypto::aesKwUnwrap(const std::shared_ptr<ArrayBuffer> &kek,
                              const std::shared_ptr<ArrayBuffer> &wrapped) {
  if (!kek || !wrapped)
    throw std::runtime_error("AES-KW unwrap: invalid input");

  // First call to get output size
  int32_t outLen = rn_crypto_aes_kw_unwrap(
      kek->data(), kek->size(), wrapped->data(), wrapped->size(), nullptr);
  if (outLen < 0) {
    throw std::runtime_error("AES-KW unwrap failed");
  }

  std::vector<uint8_t> out(outLen);
  int32_t res = rn_crypto_aes_kw_unwrap(
      kek->data(), kek->size(), wrapped->data(), wrapped->size(), out.data());
  if (res < 0) {
    throw std::runtime_error("AES-KW unwrap failed");
  }

  return ArrayBuffer::copy(out.data(), res);
}

// ==================== DH KeyObject Shared Secret ====================

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::dhComputeSecretFromKeys(
    const std::shared_ptr<HybridHybridKeyObjectSpec> &privateKey,
    const std::shared_ptr<HybridHybridKeyObjectSpec> &publicKey) {
  if (!privateKey || !publicKey)
    throw std::runtime_error("dhComputeSecretFromKeys: invalid input");

  auto privNative = std::dynamic_pointer_cast<HybridKeyObject>(privateKey);
  auto pubNative = std::dynamic_pointer_cast<HybridKeyObject>(publicKey);

  if (!privNative || !privNative->getNativeKey() || !pubNative ||
      !pubNative->getNativeKey()) {
    throw std::runtime_error("dhComputeSecretFromKeys: invalid key objects");
  }

  // First call to get length
  int32_t len = rn_crypto_dh_compute_secret_from_keys(
      privNative->getNativeKey(), pubNative->getNativeKey(), nullptr);
  if (len < 0) {
    throw std::runtime_error("dhComputeSecretFromKeys failed");
  }

  std::vector<uint8_t> out(len);
  int32_t res = rn_crypto_dh_compute_secret_from_keys(
      privNative->getNativeKey(), pubNative->getNativeKey(), out.data());
  if (res < 0) {
    throw std::runtime_error("dhComputeSecretFromKeys failed");
  }

  return ArrayBuffer::copy(out.data(), res);
}

// ==================== DH KeyObject Factory ====================

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::createKeyObjectDhPrivate(
    const std::shared_ptr<ArrayBuffer> &prime,
    const std::shared_ptr<ArrayBuffer> &generator,
    const std::shared_ptr<ArrayBuffer> &privateValue) {
  if (!prime || !generator || !privateValue)
    return nullptr;
  ::KeyObject *key = rn_crypto_key_object_new_dh_private(
      prime->data(), prime->size(), generator->data(), generator->size(),
      privateValue->data(), privateValue->size());
  if (!key)
    return nullptr;
  return std::make_shared<HybridKeyObject>(key);
}

std::shared_ptr<HybridHybridKeyObjectSpec>
HybridNodeCrypto::createKeyObjectDhPublic(
    const std::shared_ptr<ArrayBuffer> &prime,
    const std::shared_ptr<ArrayBuffer> &generator,
    const std::shared_ptr<ArrayBuffer> &publicValue) {
  if (!prime || !generator || !publicValue)
    return nullptr;
  ::KeyObject *key = rn_crypto_key_object_new_dh_public(
      prime->data(), prime->size(), generator->data(), generator->size(),
      publicValue->data(), publicValue->size());
  if (!key)
    return nullptr;
  return std::make_shared<HybridKeyObject>(key);
}

// ==================== ML-KEM Complete API ====================

MLKEMKeyPairResult HybridNodeCrypto::mlkemKeygen(double level) {
  int32_t lvl = static_cast<int32_t>(level);
  ::MLKEMKeyPair *kp = rn_crypto_mlkem_keygen(lvl);
  if (!kp) {
    throw std::runtime_error("ML-KEM Key Generation failed");
  }

  auto ek = ArrayBuffer::copy(kp->encapsulation_key, kp->encapsulation_key_len);
  auto dk = ArrayBuffer::copy(kp->decapsulation_key, kp->decapsulation_key_len);
  rn_crypto_mlkem_keypair_free(kp);

  return MLKEMKeyPairResult{ek, dk};
}

MLKEMOneshotResult HybridNodeCrypto::mlkemEncapsulate(
    double level, const std::shared_ptr<ArrayBuffer> &encapsulationKey) {
  if (!encapsulationKey)
    throw std::runtime_error("ML-KEM encapsulate: invalid encapsulation key");

  int32_t lvl = static_cast<int32_t>(level);

  // Get expected sizes
  size_t ct_cap = rn_crypto_mlkem_ct_len(lvl);
  size_t ss_cap = 32; // Shared secret is always 32 bytes

  std::vector<uint8_t> ct(ct_cap);
  std::vector<uint8_t> ss(ss_cap);
  size_t ct_len = 0, ss_len = 0;

  int32_t res = rn_crypto_mlkem_encapsulate(lvl, encapsulationKey->data(),
                                            encapsulationKey->size(), ct.data(),
                                            &ct_len, ss.data(), &ss_len);

  if (res != 0) {
    throw std::runtime_error("ML-KEM encapsulate failed");
  }

  return MLKEMOneshotResult{ArrayBuffer::copy(ct.data(), ct_len),
                            ArrayBuffer::copy(ss.data(), ss_len)};
}

std::shared_ptr<ArrayBuffer> HybridNodeCrypto::mlkemDecapsulate(
    double level, const std::shared_ptr<ArrayBuffer> &decapsulationKey,
    const std::shared_ptr<ArrayBuffer> &ciphertext) {
  if (!decapsulationKey || !ciphertext)
    throw std::runtime_error("ML-KEM decapsulate: invalid input");

  int32_t lvl = static_cast<int32_t>(level);

  std::vector<uint8_t> ss(32); // Shared secret is always 32 bytes
  size_t ss_len = 0;

  int32_t res = rn_crypto_mlkem_decapsulate(
      lvl, decapsulationKey->data(), decapsulationKey->size(),
      ciphertext->data(), ciphertext->size(), ss.data(), &ss_len);

  if (res != 0) {
    throw std::runtime_error("ML-KEM decapsulate failed");
  }

  return ArrayBuffer::copy(ss.data(), ss_len);
}

double HybridNodeCrypto::mlkemEkLen(double level) {
  return static_cast<double>(
      rn_crypto_mlkem_ek_len(static_cast<int32_t>(level)));
}

double HybridNodeCrypto::mlkemDkLen(double level) {
  return static_cast<double>(
      rn_crypto_mlkem_dk_len(static_cast<int32_t>(level)));
}

double HybridNodeCrypto::mlkemCtLen(double level) {
  return static_cast<double>(
      rn_crypto_mlkem_ct_len(static_cast<int32_t>(level)));
}

double HybridNodeCrypto::mlkemSsLen(double level) {
  return static_cast<double>(
      rn_crypto_mlkem_ss_len(static_cast<int32_t>(level)));
}

} // namespace margelo::nitro::node_crypto
