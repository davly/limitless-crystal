# Limitless::MirrorMark -- L43 Mirror-Mark v1 stamping (cohort-canonical Crystal SDK).
#
# Crystal 1.0+ port of the L43 Mirror-Mark v1 HMAC-SHA256-over-canonical-bytes
# algorithm shipped across the Go cohort (pulse / baseline / foundry / oracle /
# iris / nexus / folio) + the lore-mark-verify CLI (stdlib Go) +
# foundation/pkg/mirrormark (canonical Go package) + the Python / C++ / .NET /
# Solidity / Rust / Erlang/OTP / C99 / Gleam / Racket / Idris / Fortran /
# D / R cohort siblings.
#
# Mark format:
#     "lore@v1:" + base64url(corpusSHA[0..7] + HMAC-SHA256(0x01 + corpusSHA + payload, key))
#
# R151 KAT-1 anchor:
#     239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
#
# Reproducible offline (no Crystal toolchain involved):
#
#     printf '\x01' > /tmp/kat1.bin
#     printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
#     openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
#
# R-rule alignment:
#   - R151 KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN  -- KAT-1 hex anchor
#   - R143 LOUD-ONCE-WARNING-FLAG                       -- placeholder warning hooks
#   - R145.B SIBLING-NOT-STACKED                        -- pure primitive
#   - R157 SUBSTRATE-NATIVE-IDIOM-OVER-LITERAL-TRANSLATION
#
# Zero external dependencies (Crystal stdlib only).

require "openssl/hmac"
require "openssl/digest"
require "base64"

module Limitless
  module MirrorMark
    # --- Cohort-canonical constants (R151 KAT-1 cross-substrate pin) ---

    # 1-byte version tag prefixing the HMAC input. v1 = 0x01.
    MARK_VERSION = 0x01_u8

    # Human-readable header-value prefix. Byte-identical to
    # foundation/pkg/mirrormark.MarkPrefix.
    MARK_PREFIX = "lore@v1:"

    # Corpus-SHA prefix length embedded in the mark body.
    MARK_CORPUS_PREFIX_LEN = 8

    # SHA-256 digest size in bytes.
    SHA256_DIGEST_LEN = 32

    # Unencoded mark body length (8 bytes corpusSHA prefix + 32 bytes HMAC).
    MARK_BODY_LEN = MARK_CORPUS_PREFIX_LEN + SHA256_DIGEST_LEN

    # --- R151 KAT-1 anchor (cohort cross-substrate firewall) ---

    # KAT-1 HMAC-SHA256 digest, hex-encoded. THIS IS THE COHORT CROSS-SUBSTRATE
    # FIREWALL.
    KAT1_DIGEST_HEX = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

    # KAT-1 mark string. Byte-identical to foundation/pkg/mirrormark.KAT1Mark.
    KAT1_MARK = "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg"

    # KAT-1 input bytes: 0x01 followed by 32 x 0x00.
    def self.kat1_input : Bytes
      buf = Bytes.new(33, 0_u8)
      buf[0] = 0x01_u8
      buf
    end

    # --- Error sentinels ---

    # Base class for all Mirror-Mark errors.
    class Error < Exception
    end

    # Raised when corpus SHA isn't exactly 32 bytes.
    class InvalidCorpusLengthError < Error
      def initialize(got : Int32)
        super("mirrormark: corpus_sha must be #{SHA256_DIGEST_LEN} bytes, got #{got}")
      end
    end

    # Raised when verify() receives a mark string missing the v1 prefix.
    class UnknownMarkVersionError < Error
      def initialize
        super("mirrormark: unknown mark version (missing '#{MARK_PREFIX}' prefix)")
      end
    end

    # Raised when verify() receives a mark whose body fails base64url decode or wrong length.
    class MalformedMarkError < Error
      def initialize(detail : String)
        super("mirrormark: malformed mark (#{detail})")
      end
    end

    # Raised when the embedded corpus prefix doesn't match the supplied corpus.
    class CorpusMismatchError < Error
      def initialize
        super("mirrormark: corpus prefix mismatch (mark signed by different corpus)")
      end
    end

    # Raised when the HMAC signature doesn't match the recomputed expectation.
    class SignatureMismatchError < Error
      def initialize
        super("mirrormark: HMAC signature mismatch (payload tampered or wrong key)")
      end
    end

    # Raised when a Marker is constructed with an empty key. KAT-1 vectors use
    # an empty key; test callers can call module-level `sign` directly. The
    # Marker class refuses an empty key at construction time to keep production
    # paths fail-closed against accidental key-loss.
    class EmptyKeyError < Error
      def initialize
        super("mirrormark: Marker refuses empty HMAC key; use module-level sign() for KAT-1 vectors")
      end
    end

    # --- Internal: HMAC-SHA256 ---

    private def self.hmac_sha256(key : Bytes, data : Bytes) : Bytes
      OpenSSL::HMAC.digest(:sha256, key, data)
    end

    # --- Internal: base64url encode/decode (RFC 4648, no padding) ---

    private def self.base64url_encode(data : Bytes) : String
      Base64.urlsafe_encode(data, padding: false)
    end

    # Strict RFC 4648 base64url (no padding) alphabet. The encoded mark body
    # MUST contain only [A-Za-z0-9_-]; standard-alphabet '+' / '/' and any '='
    # padding are REJECTED. This mirrors the canonical Go verifier
    # (foundation/pkg/mirrormark/verifier.go uses base64.RawURLEncoding, which
    # is strict) and the dedicated CLIs (lore-mark-verify-ts /^[A-Za-z0-9_-]*$/;
    # lore-mark-verify-py rejects '+' '/' '='). Without this guard, Crystal's
    # `s.tr("-_","+/")` only rewrites the url-safe glyphs, so a standard-alphabet
    # (or padded) mark would decode unchanged -> input malleability on a verify
    # path (many distinct mark strings verifying the same body).
    BASE64URL_ALPHABET = /\A[A-Za-z0-9_-]*\z/

    private def self.base64url_decode(s : String) : Bytes?
      # Reject anything outside the url-safe, no-padding alphabet BEFORE decode.
      # This explicitly rejects '+', '/' and '=' (padding) that Crystal's
      # permissive Base64.decode would otherwise accept.
      return nil unless s.matches?(BASE64URL_ALPHABET)
      begin
        Base64.decode(s.tr("-_", "+/").ljust((s.size + 3) // 4 * 4, '='))
      rescue Base64::Error
        nil
      end
    end

    # --- Internal: constant-time equal ---

    private def self.constant_time_equal(a : Bytes, b : Bytes) : Bool
      return false unless a.size == b.size
      diff = 0_u8
      a.each_with_index do |byte, i|
        diff |= byte ^ b[i]
      end
      diff == 0
    end

    # --- Internal: build canonical HMAC input ---

    private def self.build_hmac_input(corpus_sha : Bytes, payload : Bytes) : Bytes
      raise InvalidCorpusLengthError.new(corpus_sha.size) unless corpus_sha.size == SHA256_DIGEST_LEN
      buf = Bytes.new(1 + corpus_sha.size + payload.size)
      buf[0] = MARK_VERSION
      corpus_sha.each_with_index { |b, i| buf[1 + i] = b }
      payload.each_with_index { |b, i| buf[1 + corpus_sha.size + i] = b }
      buf
    end

    private def self.assemble_mark(corpus_sha : Bytes, digest : Bytes) : String
      raise Error.new("digest length must be #{SHA256_DIGEST_LEN}, got #{digest.size}") unless digest.size == SHA256_DIGEST_LEN
      body = Bytes.new(MARK_BODY_LEN)
      MARK_CORPUS_PREFIX_LEN.times { |i| body[i] = corpus_sha[i] }
      digest.each_with_index { |b, i| body[MARK_CORPUS_PREFIX_LEN + i] = b }
      MARK_PREFIX + base64url_encode(body)
    end

    # --- Public API: sign / verify ---

    # Compute the canonical Mirror-Mark string for the given inputs.
    #
    # Mark format:
    #     "lore@v1:" + base64url(corpusSHA[0..7] + HMAC-SHA256(0x01 + corpusSHA + payload, key))
    #
    # Pure function. Safe to call from a cold-verify regulator binary holding
    # only (corpus_sha, payload, key).
    def self.sign(corpus_sha : Bytes, payload : Bytes, key : Bytes) : String
      input = build_hmac_input(corpus_sha, payload)
      digest = hmac_sha256(key, input)
      assemble_mark(corpus_sha, digest)
    end

    # Verify a Mirror-Mark string against (corpus_sha, payload, key).
    #
    # Returns nil on match; raises a typed sentinel error on any failure.
    def self.verify(mark : String, corpus_sha : Bytes, payload : Bytes, key : Bytes) : Nil
      raise InvalidCorpusLengthError.new(corpus_sha.size) unless corpus_sha.size == SHA256_DIGEST_LEN
      raise UnknownMarkVersionError.new unless mark.starts_with?(MARK_PREFIX)
      body = base64url_decode(mark[MARK_PREFIX.size..])
      raise MalformedMarkError.new("base64url decode failed") if body.nil?
      raise MalformedMarkError.new("body wrong length: got #{body.size}, want #{MARK_BODY_LEN}") unless body.size == MARK_BODY_LEN
      embedded_corpus = body[0, MARK_CORPUS_PREFIX_LEN]
      embedded_digest = body[MARK_CORPUS_PREFIX_LEN, SHA256_DIGEST_LEN]
      raise CorpusMismatchError.new unless constant_time_equal(embedded_corpus, corpus_sha[0, MARK_CORPUS_PREFIX_LEN])
      expected_digest = hmac_sha256(key, build_hmac_input(corpus_sha, payload))
      raise SignatureMismatchError.new unless constant_time_equal(embedded_digest, expected_digest)
      nil
    end

    # Boolean form of verify. Returns true iff the mark matches.
    def self.verify_bool(mark : String, corpus_sha : Bytes, payload : Bytes, key : Bytes) : Bool
      verify(mark, corpus_sha, payload, key)
      true
    rescue Error
      false
    end

    # --- Marker class (placeholder-tracking + LoudOnce surface) ---

    # A long-lived Mirror-Mark signer.
    #
    # Constructed with (corpus_sha, key); both are immutable post-construction.
    # Calling `mark(payload)` returns a canonical Mirror-Mark string.
    class Marker
      getter corpus_sha : Bytes
      getter key : Bytes
      getter? using_placeholder_corpus : Bool
      getter? using_placeholder_key : Bool

      def initialize(corpus_sha : Bytes, key : Bytes, @on_warn : Proc(Bool, Bool, Nil)? = nil)
        raise InvalidCorpusLengthError.new(corpus_sha.size) unless corpus_sha.size == SHA256_DIGEST_LEN
        raise EmptyKeyError.new if key.empty?
        @corpus_sha = corpus_sha.dup
        @key = key.dup
        @using_placeholder_corpus = MirrorMark.all_zero?(@corpus_sha)
        @using_placeholder_key = MirrorMark.all_zero?(@key)
        @warned_once = false
      end

      def mark(payload : Bytes) : String
        maybe_warn
        MirrorMark.sign(@corpus_sha, payload, @key)
      end

      def verify(payload : Bytes, mark_str : String) : Nil
        MirrorMark.verify(mark_str, @corpus_sha, payload, @key)
      end

      # Returns {placeholder_corpus, placeholder_key}.
      def using_placeholders : Tuple(Bool, Bool)
        {@using_placeholder_corpus, @using_placeholder_key}
      end

      private def maybe_warn
        return if @warned_once
        return unless @using_placeholder_corpus || @using_placeholder_key
        @warned_once = true
        if on_warn = @on_warn
          on_warn.call(@using_placeholder_corpus, @using_placeholder_key)
          return
        end
        parts = [] of String
        parts << "corpus" if @using_placeholder_corpus
        parts << "key" if @using_placeholder_key
        STDERR.puts("mirrormark: WARNING -- signing with placeholder #{parts.join(" ")}; " \
                    "emitted marks will NOT pass cold-verify against a real lore corpus / " \
                    "production key")
      end
    end

    def self.all_zero?(buf : Bytes) : Bool
      return true if buf.empty?
      buf.all? { |b| b == 0_u8 }
    end

    # --- KAT-1 self-test ---

    # Verify the KAT-1 anchor reproduces. Raises on drift.
    def self.assert_kat1_parity : Nil
      digest = hmac_sha256(Bytes.empty, kat1_input)
      hex = digest.hexstring
      unless hex == KAT1_DIGEST_HEX
        raise Error.new(
          "L43 Mirror-Mark KAT-1 drift detected: got #{hex}, expected #{KAT1_DIGEST_HEX}. " \
          "This breaks cohort parity with pulse / baseline / foundry / oracle / iris."
        )
      end
      nil
    end

    # Hex-encode a byte slice (lowercase, no separator).
    def self.bytes_to_hex(data : Bytes) : String
      data.hexstring
    end

    # Hex-decode a lowercase string to bytes; raises on invalid input.
    def self.hex_to_bytes(hex : String) : Bytes
      raise Error.new("hexToBytes: odd-length input (#{hex.size})") unless hex.size % 2 == 0
      raise Error.new("hexToBytes: invalid hex character in input") unless hex.matches?(/^[0-9a-fA-F]*$/)
      hex.hexbytes
    end
  end
end
