# Scratch monitor race — regression record

The budget monitor checked is_file(), then called stat(). A concurrently removed tool temporary file could raise FileNotFoundError and abort an otherwise valid operation. The outer recovery layer classifies child failure as resource_limited, so that state alone did not identify the cause.

Reproduced deterministically on GitHub before the fix:
https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/40049790649
test_tool_removing_a_checked_temporary_file_is_not_a_failure forced a real unlink between the two metadata reads and failed at item.stat() with FileNotFoundError.

Correction: tolerate only FileNotFoundError at that stat() boundary. Keep entry counts, symlink rejection, file-size limits and other errors. No resource limit was raised or disabled, and no failed tool operation is converted into a password match.

This establishes a concrete monitor defect. The earlier intermittent John/Hashcat failures were not individually traced to this exception; it must not be claimed that every previous resource_limited result had this cause. Their real integrations and the complete suites must be rerun on the corrected SHA.

The diagnostic workflow repeats real synthetic SHA256/ZIP operations in three rounds and emits only fixed error categories, integer errno and return codes. No proprietary evidence, candidate, raw argv or backend output is logged. Earlier diagnostic runs passed 12/12 on the unmodified monitor, illustrating why an occasional green run alone does not prove an intermittent defect fixed.

Remaining platform limits and the broader VisionFT/FTW2 work are documented separately in large-inputs.md and the design. This fix concerns subprocess resource monitoring (Codex sections 12/14/18), preserving the recovery protocol and other agent's branches.
