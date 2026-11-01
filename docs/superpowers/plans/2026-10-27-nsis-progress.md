# NSIS implementation ledger
Spec: docs/superpowers/specs/2026-10-23-visionft-analysis-design.md.
Authorized continuation: 2026-10-27; own existing branch/PR #27, tests only GitHub.
- RED 7083f3b: four missing-module tests failed in run 40604675927.
- Implemented bounded 7-Zip child, safe member validation, verified CORE acquisition, saved operation/report and CLI.
- Real integration identified an omitted Size field in the final member of a solid NSIS block (run 40604937940).
- Correction 9a00477: keep unknown size as null, enforce actual byte count during extraction, validate declared size when supplied.
- Pending: read fresh green results; complete regression/review evidence before claiming success.
Ruling: this increment provides fixed VisionFT selection and synchronous extraction through existing CORE operations. Full extraction queue/checkpoints and broader VisionFT modules remain pending; do not claim full original delivery.
