#include "shell/proxy_capture_filter.h"
#include <iostream>
#include <stdexcept>

using wpe::shell::CaptureFilterAllowed;
using wpe::shell::CaptureFilterMatches;

namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

CaptureFilterMatches HeaderAndType(bool header, bool type) {
    CaptureFilterMatches result;
    result.check_head = true;
    result.head_match = header;
    result.check_type = true;
    result.type_match = type;
    return result;
}
}

int main() {
    try {
        // No enabled condition is a no-op in either mode.
        Require(CaptureFilterAllowed({}) , "empty show filter must allow");
        CaptureFilterMatches empty_hide;
        empty_hide.not_show = true;
        Require(CaptureFilterAllowed(empty_hide), "empty hide filter must allow");

        // The screenshot's rule is header AND (selected category type).
        Require(CaptureFilterAllowed(HeaderAndType(true, true)),
            "matching header and category must show");
        Require(!CaptureFilterAllowed(HeaderAndType(false, true)),
            "matching category cannot bypass header");
        Require(!CaptureFilterAllowed(HeaderAndType(true, false)),
            "matching header cannot bypass category");

        // Hide mode is the original inverse: any matching enabled group hides.
        auto hide = HeaderAndType(true, true);
        hide.not_show = true;
        Require(!CaptureFilterAllowed(hide), "hide mode must hide a match");
        hide.head_match = false;
        hide.type_match = false;
        Require(CaptureFilterAllowed(hide), "hide mode must keep a non-match");

        // A header-only rule does not require a stale type selection.
        CaptureFilterMatches header_only;
        header_only.check_head = true;
        header_only.head_match = true;
        Require(CaptureFilterAllowed(header_only), "header-only match must show");
        header_only.head_match = false;
        Require(!CaptureFilterAllowed(header_only), "header-only non-match must hide");

        std::cout << "PASS: proxy capture filter AND/OR semantics" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << std::endl;
        return 1;
    }
}
