# limitless-crystal spec suite.
#
# Run: `crystal spec`
#
# Minimum 20 specs per scope requirement.
#
# R151 KAT-1 cross-substrate firewall: assert_kat1_parity must reproduce the
# canonical hex 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca.

require "spec"
require "../src/limitless_crystal"

# Helper: build a Bytes from a hex-decoded string.
private def hex(s : String) : Bytes
  Limitless::MirrorMark.hex_to_bytes(s)
end

# ---------------------------------------------------------------------------
# Mirror-Mark KAT-1 parity (R151)
# ---------------------------------------------------------------------------

describe Limitless::MirrorMark do
  describe "KAT-1 cohort cross-substrate firewall (R151)" do
    it "assert_kat1_parity matches cohort canonical" do
      Limitless::MirrorMark.assert_kat1_parity
    end

    it "KAT1_DIGEST_HEX literal is the cohort firewall pin" do
      Limitless::MirrorMark::KAT1_DIGEST_HEX.should eq(
        "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca")
    end

    it "KAT1_MARK is byte-identical across cohort" do
      Limitless::MirrorMark::KAT1_MARK.should eq(
        "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg")
    end

    it "sign() with KAT-1 inputs produces KAT-1 mark" do
      corpus = Bytes.new(32, 0_u8)
      payload = Bytes.empty
      key = Bytes.empty
      mark = Limitless::MirrorMark.sign(corpus, payload, key)
      mark.should eq(Limitless::MirrorMark::KAT1_MARK)
    end

    it "verify() accepts KAT-1 mark with KAT-1 inputs" do
      corpus = Bytes.new(32, 0_u8)
      Limitless::MirrorMark.verify(Limitless::MirrorMark::KAT1_MARK, corpus, Bytes.empty, Bytes.empty)
    end

    it "verify_bool returns true for KAT-1 round-trip" do
      corpus = Bytes.new(32, 0_u8)
      Limitless::MirrorMark.verify_bool(
        Limitless::MirrorMark::KAT1_MARK, corpus, Bytes.empty, Bytes.empty).should be_true
    end

    it "Limitless::KAT module re-exports KAT1_DIGEST_HEX" do
      Limitless::KAT::KAT1_DIGEST_HEX.should eq(Limitless::MirrorMark::KAT1_DIGEST_HEX)
    end
  end

  # ---------------------------------------------------------------------------
  # sign / verify round-trip
  # ---------------------------------------------------------------------------

  describe "sign + verify round-trip" do
    it "round-trips with non-zero corpus + payload + key" do
      corpus = Bytes.new(32) { |i| (i + 1).to_u8 }
      payload = "hello world".to_slice
      key = "my-secret-key".to_slice
      mark = Limitless::MirrorMark.sign(corpus, payload, key)
      Limitless::MirrorMark.verify(mark, corpus, payload, key)
    end

    it "verify rejects tampered payload" do
      corpus = Bytes.new(32) { |i| i.to_u8 }
      mark = Limitless::MirrorMark.sign(corpus, "original".to_slice, "k".to_slice)
      expect_raises(Limitless::MirrorMark::SignatureMismatchError) do
        Limitless::MirrorMark.verify(mark, corpus, "tampered".to_slice, "k".to_slice)
      end
    end

    it "verify rejects wrong key" do
      corpus = Bytes.new(32, 0_u8)
      mark = Limitless::MirrorMark.sign(corpus, "data".to_slice, "key1".to_slice)
      expect_raises(Limitless::MirrorMark::SignatureMismatchError) do
        Limitless::MirrorMark.verify(mark, corpus, "data".to_slice, "key2".to_slice)
      end
    end

    it "verify rejects wrong corpus" do
      corpus1 = Bytes.new(32) { |i| i.to_u8 }
      corpus2 = Bytes.new(32) { |i| (i + 100).to_u8 }
      mark = Limitless::MirrorMark.sign(corpus1, "x".to_slice, "k".to_slice)
      expect_raises(Limitless::MirrorMark::CorpusMismatchError) do
        Limitless::MirrorMark.verify(mark, corpus2, "x".to_slice, "k".to_slice)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Errors
  # ---------------------------------------------------------------------------

  describe "error cases" do
    it "sign raises InvalidCorpusLengthError for non-32-byte corpus" do
      expect_raises(Limitless::MirrorMark::InvalidCorpusLengthError) do
        Limitless::MirrorMark.sign(Bytes.new(20, 0_u8), Bytes.empty, Bytes.empty)
      end
    end

    it "verify raises UnknownMarkVersionError for missing v1 prefix" do
      expect_raises(Limitless::MirrorMark::UnknownMarkVersionError) do
        Limitless::MirrorMark.verify("not-a-mark", Bytes.new(32, 0_u8), Bytes.empty, Bytes.empty)
      end
    end

    it "verify raises MalformedMarkError for short body" do
      expect_raises(Limitless::MirrorMark::MalformedMarkError) do
        Limitless::MirrorMark.verify("lore@v1:abc", Bytes.new(32, 0_u8), Bytes.empty, Bytes.empty)
      end
    end

    # --- base64url strict-alphabet decode (verify-path malleability fix) ---
    #
    # Canonical Go (foundation/pkg/mirrormark/verifier.go) uses
    # base64.RawURLEncoding which STRICTLY rejects '+', '/' and '=' padding.
    # The dedicated CLIs do likewise (lore-mark-verify-ts /^[A-Za-z0-9_-]*$/;
    # lore-mark-verify-py rejects '+' '/' '='). Crystal's prior decode did
    # `s.tr("-_","+/")` which only rewrote the url-safe glyphs, leaving any
    # standard-alphabet '+' '/' (or '=') to pass UNCHANGED into the permissive
    # Base64.decode -> input malleability (many distinct mark strings verifying
    # the same body) on a verify path.
    #
    # KAT (derived offline; corpus=sha256("corpus1"), payload="", key="k"):
    #   valid RawURL mark : lore@v1:2Lwb_PJL-2ezXsFNcUqYZ2IgODDFnrPCp36BB9JE6djHB15vYyp2Tg
    #   std-alphabet twin : lore@v1:2Lwb/PJL+2ezXsFNcUqYZ2IgODDFnrPCp36BB9JE6djHB15vYyp2Tg
    #   padded twin       : lore@v1:2Lwb_PJL-2ezXsFNcUqYZ2IgODDFnrPCp36BB9JE6djHB15vYyp2Tg==
    describe "base64url strict alphabet (verify-path malleability)" do
      valid_mark   = "lore@v1:2Lwb_PJL-2ezXsFNcUqYZ2IgODDFnrPCp36BB9JE6djHB15vYyp2Tg"
      std_mark     = "lore@v1:2Lwb/PJL+2ezXsFNcUqYZ2IgODDFnrPCp36BB9JE6djHB15vYyp2Tg"
      padded_mark  = "lore@v1:2Lwb_PJL-2ezXsFNcUqYZ2IgODDFnrPCp36BB9JE6djHB15vYyp2Tg=="
      corpus       = hex("d8bc1bfcf24bfb6747210ebfabfa34c37bb3bb01f33cef9af9f3967b51929902")
      payload      = Bytes.empty
      key          = "k".to_slice

      it "verifies the valid RawURL-encoded mark (round-trip)" do
        Limitless::MirrorMark.verify(valid_mark, corpus, payload, key)
      end

      it "rejects a standard-alphabet ('+' '/') mark as malformed" do
        expect_raises(Limitless::MirrorMark::MalformedMarkError) do
          Limitless::MirrorMark.verify(std_mark, corpus, payload, key)
        end
      end

      it "rejects a padded ('=') mark as malformed" do
        expect_raises(Limitless::MirrorMark::MalformedMarkError) do
          Limitless::MirrorMark.verify(padded_mark, corpus, payload, key)
        end
      end

      it "verify_bool is false for the standard-alphabet twin but true for valid" do
        Limitless::MirrorMark.verify_bool(std_mark, corpus, payload, key).should be_false
        Limitless::MirrorMark.verify_bool(valid_mark, corpus, payload, key).should be_true
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Marker class
  # ---------------------------------------------------------------------------

  describe Limitless::MirrorMark::Marker do
    it "constructs with valid inputs" do
      corpus = Bytes.new(32) { |i| i.to_u8 }
      m = Limitless::MirrorMark::Marker.new(corpus, "key".to_slice)
      m.should_not be_nil
    end

    it "rejects empty key" do
      expect_raises(Limitless::MirrorMark::EmptyKeyError) do
        Limitless::MirrorMark::Marker.new(Bytes.new(32, 0_u8), Bytes.empty)
      end
    end

    it "using_placeholders detects all-zero corpus" do
      m = Limitless::MirrorMark::Marker.new(Bytes.new(32, 0_u8), "real".to_slice)
      placeholder_corpus, placeholder_key = m.using_placeholders
      placeholder_corpus.should be_true
      placeholder_key.should be_false
    end
  end

  # ---------------------------------------------------------------------------
  # Hex encode/decode
  # ---------------------------------------------------------------------------

  describe "hex round-trip" do
    it "bytes_to_hex / hex_to_bytes round-trips" do
      data = Bytes[0x01, 0x02, 0x03, 0xff, 0xab]
      hex = Limitless::MirrorMark.bytes_to_hex(data)
      hex.should eq("010203ffab")
      back = Limitless::MirrorMark.hex_to_bytes(hex)
      back.should eq(data)
    end

    it "hex_to_bytes rejects odd-length" do
      expect_raises(Limitless::MirrorMark::Error) do
        Limitless::MirrorMark.hex_to_bytes("abc")
      end
    end
  end
end

# ---------------------------------------------------------------------------
# Honest tests
# ---------------------------------------------------------------------------

describe Limitless::Honest do
  describe "LOUD_ONCE_PREFIX cohort literal pin" do
    it "is the canonical [LOUD-ONCE-WARNING]" do
      Limitless::Honest::LOUD_ONCE_PREFIX.should eq("[LOUD-ONCE-WARNING]")
    end
  end

  describe "Severity ladder" do
    it "orders INFO < WARN < ERROR < CRITICAL" do
      Limitless::Honest::Severity::INFO.rank.should be < Limitless::Honest::Severity::WARN.rank
      Limitless::Honest::Severity::WARN.rank.should be < Limitless::Honest::Severity::ERROR.rank
      Limitless::Honest::Severity::ERROR.rank.should be < Limitless::Honest::Severity::CRITICAL.rank
    end

    it "labels are SCREAMING canonical" do
      Limitless::Honest::Severity::INFO.label.should eq("INFO")
      Limitless::Honest::Severity::WARN.label.should eq("WARN")
      Limitless::Honest::Severity::ERROR.label.should eq("ERROR")
      Limitless::Honest::Severity::CRITICAL.label.should eq("CRITICAL")
    end
  end

  describe "LoudOnce.emit" do
    it "fires once and silences subsequent for same code" do
      Limitless::Honest.reset
      adv = Limitless::Honest::Advisory.new(
        code: "TEST_CODE_LO_22",
        severity: Limitless::Honest::Severity::WARN,
        message: "test message",
        doc_link: "docs/test.md"
      )
      io = IO::Memory.new
      Limitless::Honest::loud_once_singleton.emit(adv, io).should be_true
      Limitless::Honest::loud_once_singleton.emit(adv, io).should be_false
      Limitless::Honest.reset
    end

    it "emit_all counts only fresh emissions" do
      Limitless::Honest.reset
      advs = [
        Limitless::Honest::Advisory.new("LO_CODE_A", Limitless::Honest::Severity::INFO, "a", "x"),
        Limitless::Honest::Advisory.new("LO_CODE_B", Limitless::Honest::Severity::WARN, "b", "y"),
        Limitless::Honest::Advisory.new("LO_CODE_A", Limitless::Honest::Severity::INFO, "a-dup", "x"),
      ]
      io = IO::Memory.new
      fresh = Limitless::Honest.emit_all(advs, io)
      fresh.should eq(2)
      Limitless::Honest.reset
    end
  end
end

# ---------------------------------------------------------------------------
# Legal tests
# ---------------------------------------------------------------------------

describe Limitless::Legal do
  describe "honest defaults (R150)" do
    it "DEFAULT_REVIEWED_BY_COUNSEL is false" do
      Limitless::Legal::DEFAULT_REVIEWED_BY_COUNSEL.should be_false
    end
  end

  describe "UK GDPR statutory refs (cohort byte-aligned)" do
    it "REF_UK_GDPR_ARTICLE_9 cohort literal" do
      Limitless::Legal::REF_UK_GDPR_ARTICLE_9.should eq("UK GDPR Article 9")
    end
  end

  describe "DocumentID closed-set" do
    it "accepts all five canonical slugs" do
      ["terms", "privacy", "cookies", "gdpr", "community-guidelines"].each do |slug|
        Limitless::Legal.valid_document_id?(slug).should be_true
      end
      Limitless::Legal.valid_document_id?("invalid").should be_false
    end
  end

  describe "computeBodyHash" do
    it "returns SHA-256 hex of empty string (cross-substrate parity)" do
      hex = Limitless::Legal.compute_body_hash("")
      hex.should eq("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    end
  end

  describe "LegalConfig.configured?" do
    it "rejects empty operator-name" do
      cfg = Limitless::Legal::LegalConfig.new(
        operator_name: "",
        registered_office_address: "addr",
        ico_registration_number: "ZX0000000",
        dpo_email: "dpo@x.y",
        contact_email: "x@y.z",
        jurisdiction: "England",
        service_name: "svc",
        vat_number: "",
        company_number: "",
      )
      Limitless::Legal.configured?(cfg).should be_false
    end

    it "accepts fully-populated config" do
      cfg = Limitless::Legal::LegalConfig.new(
        operator_name: "Acme",
        registered_office_address: "1 Main St",
        ico_registration_number: "ZA000001",
        dpo_email: "dpo@acme.com",
        contact_email: "legal@acme.com",
        jurisdiction: "England and Wales",
        service_name: "Acme",
        vat_number: "",
        company_number: "",
      )
      Limitless::Legal.configured?(cfg).should be_true
    end
  end

  describe "body_with_placeholder_alert (R166)" do
    it "prepends DEFAULT_PLACEHOLDER_ALERT when not-reviewed" do
      cfg = Limitless::Legal.placeholder
      p = Limitless::Legal.new_page("terms", "Terms", "1.0", "2026-01-01", "Body.", false, cfg)
      rendered = Limitless::Legal.body_with_placeholder_alert(p)
      rendered.starts_with?(Limitless::Legal::DEFAULT_PLACEHOLDER_ALERT).should be_true
    end

    it "returns body unchanged when reviewed" do
      cfg = Limitless::Legal.placeholder
      p = Limitless::Legal.new_page("terms", "Terms", "1.0", "2026-01-01", "Body.", true, cfg)
      Limitless::Legal.body_with_placeholder_alert(p).should eq("Body.")
    end
  end

  describe "acceptance_key cohort form" do
    it "produces pipe-delimited key" do
      Limitless::Legal.acceptance_key("user1", "terms", "1.0").should eq("user1|terms|1.0")
    end
  end

  describe "DEFAULT_PLACEHOLDER_ALERT cohort literal (R166)" do
    it "begins with IMPORTANT:" do
      Limitless::Legal::DEFAULT_PLACEHOLDER_ALERT.starts_with?("IMPORTANT:").should be_true
    end
  end
end
