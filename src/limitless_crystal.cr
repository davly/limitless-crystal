# Limitless Crystal SDK -- top-level shim.
#
# Re-exports the four cohort primitives:
#   - Limitless::MirrorMark -- L43 Mirror-Mark v1 sign/verify
#   - Limitless::Honest     -- R143 LOUD-ONCE-WARNING-FLAG
#   - Limitless::Legal      -- R166 LIABILITY-FOOTER-CONST + UK GDPR refs
#   - Limitless::KAT        -- KAT-1 parity assertion
#
# R151 KAT-1 anchor:
#     239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca

require "./mirrormark"
require "./honest"
require "./legal"
require "./kat"

module Limitless
  VERSION = "0.1.0"
end
