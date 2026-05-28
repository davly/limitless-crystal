# Limitless::Legal -- UK GDPR + statutory cross-reference surface (cohort-canonical Crystal SDK).
#
# Crystal 1.0+ port of foundation/legal/{refs.go, types.go, config.go, page.go}
# (Go canonical) + the cohort siblings.
#
# R166 LIABILITY-FOOTER-CONST alignment:
#   - DEFAULT_PLACEHOLDER_ALERT is the cohort-canonical liability-footer constant.
#   - DEFAULT_REVIEWED_BY_COUNSEL = false is the cohort-canonical honest-default.
#
# R-rule alignment:
#   - R166 LIABILITY-FOOTER-CONST
#   - R154 ARTICLE-9-DSAR-AUDIT-CLASS-COHORT-EXTENSION
#   - R150 PARALLEL-MAP-R144-REVIEW-METADATA

require "openssl/digest"

module Limitless
  module Legal
    # --- UK GDPR statutory references (cohort byte-aligned with foundation/legal/refs.go) ---

    REF_UK_GDPR_ARTICLE_9  = "UK GDPR Article 9"
    REF_UK_GDPR_ARTICLE_13 = "UK GDPR Article 13"
    REF_UK_GDPR_ARTICLE_14 = "UK GDPR Article 14"
    REF_UK_GDPR_ARTICLE_15 = "UK GDPR Article 15"
    REF_UK_GDPR_ARTICLE_16 = "UK GDPR Article 16"
    REF_UK_GDPR_ARTICLE_17 = "UK GDPR Article 17"
    REF_UK_GDPR_ARTICLE_18 = "UK GDPR Article 18"
    REF_UK_GDPR_ARTICLE_20 = "UK GDPR Article 20"
    REF_UK_GDPR_ARTICLE_21 = "UK GDPR Article 21"
    REF_UK_GDPR_ARTICLE_30 = "UK GDPR Article 30"
    REF_UK_GDPR_ARTICLE_37 = "UK GDPR Article 37"
    REF_UK_GDPR_ARTICLE_46 = "UK GDPR Article 46"

    REF_DPA_2018_SECTION_17  = "DPA 2018 s17"
    REF_PECR_REGULATION_6    = "PECR Regulation 6"
    REF_UK_LIMITATION_ACT_1980 = "UK Limitation Act 1980"
    REF_FSMA_2000_SECTION_19 = "FSMA 2000 s19"

    # --- Cohort-canonical legal text constants ---

    ARTICLE_9_MENTAL_HEALTH_NOTICE = \
      "Mental-health observations, mood entries, crisis events, and safety-plan " \
      "records processed by this service are special category of personal data " \
      "under UK GDPR Article 9(1). Processing requires a lawful basis under " \
      "Article 6 PLUS a separate lawful basis under Article 9(2). The typical " \
      "Article 9(2) bases are: (a) explicit consent freely given by the data " \
      "subject, (c) protection of the vital interests of the data subject in a " \
      "crisis where the subject is incapable of giving consent, (g) substantial " \
      "public interest under a basis in domestic law, or (h) provision of " \
      "health or social care under a contract with a health professional. The " \
      "operator MUST document which Article 9(2) lawful basis is being relied " \
      "upon and surface it in the privacy notice. You have the rights of " \
      "access, rectification, erasure, restriction, portability, and objection " \
      "under Articles 15, 16, 17, 18, 20, and 21."

    FCA_NOT_AUTHORISED_DISCLAIMER = \
      "This service provides general personal-finance information only. It is NOT " \
      "regulated investment, mortgage, insurance, or pensions advice within the " \
      "meaning of FSMA 2000 s19. The operator is not authorised or regulated by " \
      "the Financial Conduct Authority. For regulated advice, consult an FCA-" \
      "authorised independent financial adviser (see fca.org.uk/register)."

    ICO_COMPLAINT_NOTICE = \
      "You have the right to lodge a complaint with the UK Information " \
      "Commissioner's Office (ICO) at any time. Visit ico.org.uk for contact " \
      "details."

    # R166 LIABILITY-FOOTER-CONST: honest-defaults LOUD banner.
    DEFAULT_PLACEHOLDER_ALERT = \
      "IMPORTANT: This document is structured boilerplate and has not been " \
      "reviewed by qualified legal counsel. Do not rely on this text as a " \
      "substitute for a professionally-drafted document before processing " \
      "customer payments."

    # R150-aligned honest-default constant.
    DEFAULT_REVIEWED_BY_COUNSEL = false

    # --- DocumentID closed-set ---

    DOCUMENT_ID_TERMS                = "terms"
    DOCUMENT_ID_PRIVACY              = "privacy"
    DOCUMENT_ID_COOKIES              = "cookies"
    DOCUMENT_ID_GDPR                 = "gdpr"
    DOCUMENT_ID_COMMUNITY_GUIDELINES = "community-guidelines"

    ALL_DOCUMENT_IDS = [
      DOCUMENT_ID_TERMS, DOCUMENT_ID_PRIVACY, DOCUMENT_ID_COOKIES,
      DOCUMENT_ID_GDPR, DOCUMENT_ID_COMMUNITY_GUIDELINES,
    ]

    def self.valid_document_id?(slug : String) : Bool
      ALL_DOCUMENT_IDS.includes?(slug)
    end

    # --- Page projection ---

    record Page,
      id : String,
      slug : String,
      title : String,
      version : String,
      effective_date : String,   # YYYY-MM-DD
      body : String,
      body_hash : String,
      reviewed_by_counsel : Bool,
      operator_name : String,
      operator_jurisdiction : String,
      operator_contact_email : String,
      operator_ico_registration : String,
      fetched_at : String        # ISO-8601 UTC

    record IndexEntry,
      id : String,
      slug : String,
      title : String,
      version : String,
      effective_date : String,
      reviewed_by_counsel : Bool

    record Index,
      operator_name : String,
      operator_jurisdiction : String,
      operator_contact_email : String,
      documents : Array(IndexEntry),
      fetched_at : String

    record Acceptance,
      user_id : String,
      document_id : String,
      version : String,
      body_hash : String,
      accepted_at : String,
      accepted_from_ip : String,
      user_agent : String

    # Cohort-aligned canonical lookup key. Format: "user_id|document_id|version".
    def self.acceptance_key(user_id : String, document_id : String, version : String) : String
      "#{user_id}|#{document_id}|#{version}"
    end

    # --- LegalConfig ---

    record LegalConfig,
      operator_name : String,
      registered_office_address : String,
      ico_registration_number : String,
      dpo_email : String,
      contact_email : String,
      jurisdiction : String,
      service_name : String,
      vat_number : String,
      company_number : String

    def self.configured?(cfg : LegalConfig) : Bool
      !cfg.operator_name.empty? &&
        !cfg.registered_office_address.empty? &&
        !cfg.ico_registration_number.empty? &&
        !cfg.contact_email.empty?
    end

    # Return a LegalConfig populated with REPLACE-IN-PRODUCTION placeholders.
    def self.placeholder : LegalConfig
      LegalConfig.new(
        operator_name: "Operator (REPLACE-IN-PRODUCTION)",
        registered_office_address: "Address (REPLACE-IN-PRODUCTION)",
        ico_registration_number: "ZX0000000",
        dpo_email: "dpo@operator.example",
        contact_email: "legal@operator.example",
        jurisdiction: "England and Wales",
        service_name: "Service (REPLACE-IN-PRODUCTION)",
        vat_number: "",
        company_number: "",
      )
    end

    # --- Page helpers ---

    # SHA-256 hex digest of a UTF-8-encoded string.
    # Byte-identical algorithm to foundation/legal/page.ComputeBodyHash.
    def self.compute_body_hash(body : String) : String
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(body)
      digest.final.hexstring
    end

    # Construct a Page with body_hash + fetched_at populated.
    def self.new_page(id : String, title : String, version : String, effective_date : String,
                      body : String, reviewed_by_counsel : Bool, cfg : LegalConfig) : Page
      Page.new(
        id: id,
        slug: id,
        title: title,
        version: version,
        effective_date: effective_date,
        body: body,
        body_hash: compute_body_hash(body),
        reviewed_by_counsel: reviewed_by_counsel,
        operator_name: cfg.operator_name,
        operator_jurisdiction: cfg.jurisdiction,
        operator_contact_email: cfg.contact_email,
        operator_ico_registration: cfg.ico_registration_number,
        fetched_at: Time.utc.to_rfc3339,
      )
    end

    # Project a Page to its slim IndexEntry form.
    def self.page_as_index_entry(page : Page) : IndexEntry
      IndexEntry.new(
        id: page.id,
        slug: page.slug,
        title: page.title,
        version: page.version,
        effective_date: page.effective_date,
        reviewed_by_counsel: page.reviewed_by_counsel,
      )
    end

    # Return the document body prefixed with DEFAULT_PLACEHOLDER_ALERT when un-reviewed.
    #
    # R166 LIABILITY-FOOTER-CONST.
    def self.body_with_placeholder_alert(page : Page) : String
      return page.body if page.reviewed_by_counsel
      return page.body if page.body.starts_with?(DEFAULT_PLACEHOLDER_ALERT)
      DEFAULT_PLACEHOLDER_ALERT + "\n\n" + page.body
    end

    # Return a plain-text rendering of the page suitable for direct response.
    def self.render_baseline(page : Page) : String
      "#{page.title}\n\nVersion: #{page.version}  Effective: #{page.effective_date}\n\n" +
        body_with_placeholder_alert(page)
    end
  end
end
