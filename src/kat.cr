# Limitless::KAT -- KAT-1 cross-substrate parity assertion (cohort-canonical Crystal SDK).
#
# Re-exports the KAT-1 anchor + assert_kat1_parity for callers that want a
# single `require "limitless/kat"` for parity-test wiring.
#
# R151 KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN: the KAT-1 hex
# 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca is the
# cohort firewall.

require "./mirrormark"

module Limitless
  module KAT
    KAT1_DIGEST_HEX = Limitless::MirrorMark::KAT1_DIGEST_HEX
    KAT1_MARK       = Limitless::MirrorMark::KAT1_MARK

    def self.kat1_input : Bytes
      Limitless::MirrorMark.kat1_input
    end

    def self.assert_parity : Nil
      Limitless::MirrorMark.assert_kat1_parity
    end
  end
end
