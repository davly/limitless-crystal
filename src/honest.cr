# Limitless::Honest -- R143 LOUD-ONCE-WARNING-FLAG primitive (cohort-canonical Crystal SDK).
#
# Crystal 1.0+ port of the R143 LOUD-ONCE-WARNING-FLAG pattern shipped across
# the Go cohort, every Python flagship adopter, the Erlang
# `limitless_beam_loud_once`, the Rust `honest` module, and the TS / D /
# Fortran / R cohort siblings.
#
# The R143 contract:
#   - First emission for a given code: write the formatted advisory, return true.
#   - Subsequent emissions for the same code: silent, return false.
#   - reset() re-arms emission (test-only).
#
# R143.A SEVERITY-LADDER-CONVENTION: closed-set severity vocabulary.
#
# R145.B SIBLING-NOT-STACKED design note:
#   This SDK ships the LoudOnce primitive + Severity vocab + Advisory type.
#   It does NOT ship per-flagship canonical advisories.
#
# Cohort literal pin:
#   The line prefix `[LOUD-ONCE-WARNING]` is byte-identical to every cohort
#   adopter.

module Limitless
  module Honest
    # Cohort-canonical line prefix for every LoudOnce emission.
    LOUD_ONCE_PREFIX = "[LOUD-ONCE-WARNING]"

    # Closed-enum severity vocabulary.
    enum Severity
      INFO     = 0
      WARN     = 1
      ERROR    = 2
      CRITICAL = 3

      # Cohort-canonical SCREAMING label form.
      def label : String
        case self
        in .info?     then "INFO"
        in .warn?     then "WARN"
        in .error?    then "ERROR"
        in .critical? then "CRITICAL"
        end
      end

      # Numeric ladder rank (higher = more severe).
      def rank : Int32
        self.value
      end
    end

    # All severity literals in ladder order (lowest -> highest).
    SEVERITY_LADDER = [Severity::INFO, Severity::WARN, Severity::ERROR, Severity::CRITICAL] of Severity

    # A single boot-time advisory.
    #
    # Fields:
    #   code:     short stable identifier; used as the LoudOnce dedupe key.
    #   severity: Severity literal value.
    #   message:  human-readable message text (single-paragraph; \n allowed).
    #   doc_link: file:line or URL pointing to the canonical source.
    record Advisory,
      code : String,
      severity : Severity,
      message : String,
      doc_link : String

    # Module-level singleton.
    class LoudOnceSingleton
      def initialize
        @seen = {} of String => Bool
        @host_prefix = "limitless"
      end

      def set_host_prefix(prefix : String) : Nil
        @host_prefix = prefix
      end

      def get_host_prefix : String
        @host_prefix
      end

      # Emit advisory iff this is the first emission for the code.
      # Returns true on first emission, false on subsequent emissions.
      def emit(advisory : Advisory, io : IO = STDERR) : Bool
        return false if @seen.has_key?(advisory.code)
        @seen[advisory.code] = true
        io.puts(format_line(advisory))
        true
      end

      def format_line(advisory : Advisory) : String
        "#{@host_prefix} #{LOUD_ONCE_PREFIX} #{advisory.severity.label} " \
          "#{advisory.code}: #{advisory.message} (see #{advisory.doc_link})"
      end

      def has_emitted?(code : String) : Bool
        @seen.has_key?(code)
      end

      def cardinality : Int32
        @seen.size
      end

      # Re-arm all emission. TEST-ONLY.
      def reset : Nil
        @seen.clear
        @host_prefix = "limitless"
      end
    end

    @@loud_once = LoudOnceSingleton.new

    # Singleton accessor.
    def self.loud_once_singleton : LoudOnceSingleton
      @@loud_once
    end

    # Cohort-canonical free function. Emits advisory iff this is the first
    # call for its code; subsequent calls with the same code are silent.
    def self.loud_once(advisory : Advisory, io : IO = STDERR) : Bool
      @@loud_once.emit(advisory, io)
    end

    # Reset the once-registry. TEST-ONLY.
    def self.reset : Nil
      @@loud_once.reset
    end

    # Emit every advisory in the input once. Returns count emitted-fresh.
    def self.emit_all(advisories : Array(Advisory), io : IO = STDERR) : Int32
      emitted_fresh = 0
      advisories.each do |adv|
        emitted_fresh += 1 if @@loud_once.emit(adv, io)
      end
      emitted_fresh
    end
  end
end
