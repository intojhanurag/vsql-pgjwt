// Copyright (c) 2026 VillageSQL Contributors
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.

#include <villagesql/vsql.h>

#include <cctype>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

using namespace vsql;

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64url_encode(const unsigned char *data, size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    unsigned int val = data[i] << 16;
    if (i + 1 < len) val |= data[i + 1] << 8;
    if (i + 2 < len) val |= data[i + 2];
    out += kBase64Chars[(val >> 18) & 0x3F];
    out += kBase64Chars[(val >> 12) & 0x3F];
    out += (i + 1 < len) ? kBase64Chars[(val >> 6) & 0x3F] : '=';
    out += (i + 2 < len) ? kBase64Chars[val & 0x3F] : '=';
  }
  for (auto &c : out) {
    if (c == '+')
      c = '-';
    else if (c == '/')
      c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

static std::string base64url_encode(std::string_view sv) {
  return base64url_encode(reinterpret_cast<const unsigned char *>(sv.data()),
                          sv.size());
}

static constexpr auto make_b64_table() {
  struct Table {
    int data[256]{};
    constexpr Table() {
      const char chars[] =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      for (int i = 0; i < 256; i++) data[i] = -1;
      for (int i = 0; i < 64; i++)
        data[static_cast<unsigned char>(chars[i])] = i;
    }
  };
  return Table();
}

static constexpr auto kB64Table = make_b64_table();

static bool base64url_decode(std::string_view input, std::string &out) {
  // RFC 7515 base64url carries no padding, and a length of 1 mod 4 cannot
  // encode any byte sequence. Reject both rather than decoding around them.
  if (input.find('=') != std::string_view::npos) return false;
  if (input.size() % 4 == 1) return false;

  std::string b64;
  b64.reserve(input.size() + 4);
  for (char c : input) {
    if (c == '-')
      b64 += '+';
    else if (c == '_')
      b64 += '/';
    else
      b64 += c;
  }
  while (b64.size() % 4 != 0) b64 += '=';

  out.clear();
  out.reserve(b64.size() * 3 / 4);
  for (size_t i = 0; i + 3 < b64.size(); i += 4) {
    int v[4];
    int pad = 0;
    for (int j = 0; j < 4; j++) {
      if (b64[i + j] == '=') {
        v[j] = 0;
        pad++;
      } else {
        v[j] = kB64Table.data[static_cast<unsigned char>(b64[i + j])];
        if (v[j] < 0) return false;
      }
    }
    unsigned int combined =
        (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    out += static_cast<char>((combined >> 16) & 0xFF);
    if (pad < 2) out += static_cast<char>((combined >> 8) & 0xFF);
    if (pad < 1) out += static_cast<char>(combined & 0xFF);
  }
  return true;
}

static const EVP_MD *get_hmac_md(std::string_view alg) {
  if (alg == "HS256") return EVP_sha256();
  if (alg == "HS384") return EVP_sha384();
  if (alg == "HS512") return EVP_sha512();
  return nullptr;
}

static bool is_hmac_alg(std::string_view alg) {
  return alg == "HS256" || alg == "HS384" || alg == "HS512";
}

static bool is_rsa_alg(std::string_view alg) { return alg == "RS256"; }

static bool hmac_sign(std::string_view data, std::string_view key,
                      const EVP_MD *md, std::string &out) {
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (!HMAC(md, key.data(), static_cast<int>(key.size()),
            reinterpret_cast<const unsigned char *>(data.data()), data.size(),
            buf, &len)) {
    return false;
  }
  out = base64url_encode(buf, len);
  return true;
}

static bool rsa_sign(std::string_view data, std::string_view pem_key,
                     std::string &out) {
  BIO *bio =
      BIO_new_mem_buf(pem_key.data(), static_cast<int>(pem_key.size()));
  if (!bio) return false;

  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey) return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
      EVP_DigestSignUpdate(ctx, data.data(), data.size()) == 1) {
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) == 1) {
      std::vector<unsigned char> sig(sig_len);
      if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) == 1) {
        out = base64url_encode(sig.data(), sig_len);
        ok = true;
      }
    }
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

static bool rsa_verify_sig(std::string_view data, std::string_view sig_b64url,
                           std::string_view pem_key) {
  std::string sig_raw;
  if (!base64url_decode(sig_b64url, sig_raw)) return false;

  BIO *bio =
      BIO_new_mem_buf(pem_key.data(), static_cast<int>(pem_key.size()));
  if (!bio) return false;

  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey) return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
      EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1) {
    ok = (EVP_DigestVerifyFinal(
              ctx, reinterpret_cast<const unsigned char *>(sig_raw.data()),
              sig_raw.size()) == 1);
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

static bool split_token(std::string_view token, std::string_view &header,
                        std::string_view &payload,
                        std::string_view &signature) {
  auto dot1 = token.find('.');
  if (dot1 == std::string_view::npos) return false;
  auto dot2 = token.find('.', dot1 + 1);
  if (dot2 == std::string_view::npos) return false;
  if (token.find('.', dot2 + 1) != std::string_view::npos) return false;

  header = token.substr(0, dot1);
  payload = token.substr(dot1 + 1, dot2 - dot1 - 1);
  signature = token.substr(dot2 + 1);
  return true;
}

static bool is_json_space(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

// Index of the closing quote of the string starting at `open` (which must be
// the opening quote), or npos if unterminated. A quote preceded by an odd
// number of backslashes is escaped and does not close the string.
static size_t json_string_end(std::string_view json, size_t open) {
  for (size_t i = open + 1; i < json.size(); i++) {
    if (json[i] == '\\') {
      i++;  // skip the escaped character, whatever it is
      continue;
    }
    if (json[i] == '"') return i;
  }
  return std::string_view::npos;
}

// Structural check: `json` is one balanced object, with every string
// terminated, and nothing but whitespace after the closing brace. Enough to
// guarantee the value can be spliced into a larger JSON document without
// corrupting it; it does not validate value grammar.
static bool json_is_wellformed_object(std::string_view json) {
  size_t i = 0;
  while (i < json.size() && is_json_space(json[i])) i++;
  if (i >= json.size() || json[i] != '{') return false;

  int depth = 0;
  for (; i < json.size(); i++) {
    char c = json[i];
    if (c == '"') {
      size_t end = json_string_end(json, i);
      if (end == std::string_view::npos) return false;
      i = end;
      continue;
    }
    if (c == '{' || c == '[') {
      depth++;
      continue;
    }
    if (c == '}' || c == ']') {
      if (--depth == 0) break;
      if (depth < 0) return false;
      continue;
    }
  }
  if (depth != 0) return false;

  for (i++; i < json.size(); i++) {
    if (!is_json_space(json[i])) return false;
  }
  return true;
}

enum class ClaimResult {
  kAbsent,   // key not present at the top level
  kParsed,   // key present and read into `val`
  kMalformed // key present but not a usable integer
};

static ClaimResult extract_json_int(std::string_view json, const char *key,
                                    long long &val) {
  std::string pat = "\"";
  pat += key;
  pat += "\"";

  int depth = 0;
  for (size_t i = 0; i < json.size(); i++) {
    char c = json[i];
    if (c == '{' || c == '[') {
      depth++;
      continue;
    }
    if (c == '}' || c == ']') {
      depth--;
      continue;
    }
    if (c != '"') continue;

    size_t end = json_string_end(json, i);
    if (end == std::string_view::npos) return ClaimResult::kMalformed;
    if (depth != 1 || json.substr(i, end - i + 1) != pat) {
      i = end;
      continue;
    }

    // Found the key at the top level. From here every exit is terminal: a
    // second occurrence must not be consulted, and an unusable value must
    // never read as "no expiry set".
    size_t pos = end + 1;
    while (pos < json.size() && is_json_space(json[pos])) pos++;
    if (pos >= json.size() || json[pos] != ':') return ClaimResult::kMalformed;
    pos++;
    while (pos < json.size() && is_json_space(json[pos])) pos++;
    if (pos >= json.size()) return ClaimResult::kMalformed;

    bool neg = false;
    if (json[pos] == '-') {
      neg = true;
      pos++;
    }
    if (pos >= json.size() ||
        !std::isdigit(static_cast<unsigned char>(json[pos])))
      return ClaimResult::kMalformed;

    long long num = 0;
    int digits = 0;
    while (pos < json.size() &&
           std::isdigit(static_cast<unsigned char>(json[pos]))) {
      if (++digits > 18) return ClaimResult::kMalformed;
      num = num * 10 + (json[pos] - '0');
      pos++;
    }
    // A fractional or exponent part means this is not a NumericDate integer.
    if (pos < json.size() && (json[pos] == '.' || json[pos] == 'e' ||
                              json[pos] == 'E'))
      return ClaimResult::kMalformed;

    val = neg ? -num : num;
    return ClaimResult::kParsed;
  }
  return ClaimResult::kAbsent;
}

static bool constant_time_eq(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  unsigned char result = 0;
  for (size_t i = 0; i < a.size(); i++) {
    result |= static_cast<unsigned char>(a[i]) ^
              static_cast<unsigned char>(b[i]);
  }
  return result == 0;
}

// jwt_sign(payload TEXT, secret TEXT, algorithm TEXT) -> TEXT
void vdf_jwt_sign(StringArg payload_arg, StringArg secret_arg,
                  StringArg algorithm_arg, StringResult out) {
  if (payload_arg.is_null() || secret_arg.is_null() ||
      algorithm_arg.is_null()) {
    out.set_null();
    return;
  }

  auto payload = payload_arg.value();
  auto secret = secret_arg.value();
  auto alg = algorithm_arg.value();

  if (!is_hmac_alg(alg) && !is_rsa_alg(alg)) {
    out.error("unsupported algorithm; use HS256, HS384, HS512, or RS256");
    return;
  }

  std::string header = "{\"alg\":\"";
  header += alg;
  header += "\",\"typ\":\"JWT\"}";

  std::string header_b64 = base64url_encode(header);
  std::string payload_b64 = base64url_encode(payload);
  std::string signable = header_b64 + "." + payload_b64;

  std::string sig_b64;
  if (is_hmac_alg(alg)) {
    const EVP_MD *md = get_hmac_md(alg);
    if (!hmac_sign(signable, secret, md, sig_b64)) {
      out.error("HMAC signing failed");
      return;
    }
  } else {
    if (!rsa_sign(signable, secret, sig_b64)) {
      out.error(
          "RSA signing failed; check that the key is a valid PEM private key");
      return;
    }
  }

  std::string token = signable + "." + sig_b64;
  out.set(std::string_view(token));
}

// jwt_verify(token TEXT, secret TEXT, algorithm TEXT) -> TEXT
void vdf_jwt_verify(StringArg token_arg, StringArg secret_arg,
                    StringArg algorithm_arg, StringResult out) {
  if (token_arg.is_null() || secret_arg.is_null() ||
      algorithm_arg.is_null()) {
    out.set_null();
    return;
  }

  auto token = token_arg.value();
  auto secret = secret_arg.value();
  auto alg = algorithm_arg.value();

  if (!is_hmac_alg(alg) && !is_rsa_alg(alg)) {
    out.warning("unsupported algorithm; use HS256, HS384, HS512, or RS256");
    return;
  }

  std::string_view hdr_b64, pay_b64, sig_b64;
  if (!split_token(token, hdr_b64, pay_b64, sig_b64)) {
    out.warning("malformed token; expected header.payload.signature");
    return;
  }

  std::string header_json, payload_json;
  if (!base64url_decode(hdr_b64, header_json) ||
      !base64url_decode(pay_b64, payload_json)) {
    out.warning("invalid base64url encoding in token");
    return;
  }

  if (!json_is_wellformed_object(header_json) ||
      !json_is_wellformed_object(payload_json)) {
    out.warning("token segments are not valid JSON objects");
    return;
  }

  std::string signable(hdr_b64);
  signable += '.';
  signable += pay_b64;

  bool sig_ok = false;
  if (is_hmac_alg(alg)) {
    const EVP_MD *md = get_hmac_md(alg);
    std::string expected_sig;
    if (hmac_sign(signable, secret, md, expected_sig)) {
      sig_ok = constant_time_eq(expected_sig, sig_b64);
    }
  } else {
    sig_ok = rsa_verify_sig(signable, sig_b64, secret);
  }

  bool time_ok = true;
  if (sig_ok) {
    time_t now = time(nullptr);
    long long exp_val;
    switch (extract_json_int(payload_json, "exp", exp_val)) {
      case ClaimResult::kParsed:
        if (now >= static_cast<time_t>(exp_val)) time_ok = false;
        break;
      case ClaimResult::kMalformed:
        time_ok = false;  // an exp we cannot read is not an exp we can honour
        break;
      case ClaimResult::kAbsent:
        break;
    }
    long long nbf_val;
    switch (extract_json_int(payload_json, "nbf", nbf_val)) {
      case ClaimResult::kParsed:
        if (now < static_cast<time_t>(nbf_val)) time_ok = false;
        break;
      case ClaimResult::kMalformed:
        time_ok = false;
        break;
      case ClaimResult::kAbsent:
        break;
    }
  }

  bool valid = sig_ok && time_ok;

  std::string result = "{\"valid\":";
  result += (valid ? "true" : "false");
  result += ",\"header\":";
  result += header_json;
  result += ",\"payload\":";
  result += payload_json;
  result += "}";

  out.set(std::string_view(result));
}

// jwt_decode(token TEXT) -> TEXT
void vdf_jwt_decode(StringArg token_arg, StringResult out) {
  if (token_arg.is_null()) {
    out.set_null();
    return;
  }

  auto token = token_arg.value();

  std::string_view hdr_b64, pay_b64, sig_b64;
  if (!split_token(token, hdr_b64, pay_b64, sig_b64)) {
    out.warning("malformed token; expected header.payload.signature");
    return;
  }

  std::string header_json, payload_json;
  if (!base64url_decode(hdr_b64, header_json) ||
      !base64url_decode(pay_b64, payload_json)) {
    out.warning("invalid base64url encoding in token");
    return;
  }

  if (!json_is_wellformed_object(header_json) ||
      !json_is_wellformed_object(payload_json)) {
    out.warning("token segments are not valid JSON objects");
    return;
  }

  std::string result = "{\"header\":";
  result += header_json;
  result += ",\"payload\":";
  result += payload_json;
  result += "}";

  out.set(std::string_view(result));
}

VEF_GENERATE_ENTRY_POINTS(
    make_extension()
        .func(make_func<&vdf_jwt_sign>("jwt_sign")
                  .returns(STRING)
                  .param(STRING)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(90000)
                  .deterministic()
                  .build())
        .func(make_func<&vdf_jwt_verify>("jwt_verify")
                  .returns(STRING)
                  .param(STRING)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(90000)
                  .build())
        .func(make_func<&vdf_jwt_decode>("jwt_decode")
                  .returns(STRING)
                  .param(STRING)
                  .buffer_size(90000)
                  .deterministic()
                  .build()))
