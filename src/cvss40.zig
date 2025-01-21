const std = @import("std");
const types = @import("./types.zig");
const util = @import("./util.zig");
const testing = std.testing;

pub fn score(cvss: []const u8) !types.CvssScore {
    util.debug("{}", .{cvss.len});
    return types.CvssScore{ .score = 0.0, .level = util.levelFromScore(0.0) };
}

test "a bunch of scoring tests" {
    const assertions = [_]struct { []const u8, f32, types.CVSS_LEVEL }{
        .{ "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Clear", 7.3, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Red", 7.3, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 5.2, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.3, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L/CR:H/IR:L/AR:L", 8.1, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.6, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D", 8.3, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", 8.7, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", 10.0, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H", 6.4, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", 9.3, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", 8.7, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 8.6, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L", 8.7, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U", 6.6, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.3, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U", 5.6, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.2, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N", 6.9, types.CVSS_LEVEL.MEDIUM },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H", 7.8, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P", 8.5, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L", 9.4, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:L/CR:L/IR:H/AR:L", 7.0, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S/CR:L/IR:H/AR:H", 7.4, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S/CR:L/IR:H/AR:H", 7.4, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S/CR:L/IR:H/AR:H", 7.4, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P", 8.6, types.CVSS_LEVEL.HIGH },
        .{ "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P", 9.7, types.CVSS_LEVEL.CRITICAL },
        .{ "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C", 8.7, types.CVSS_LEVEL.HIGH },
    };

    for (assertions) |assertion| {
        const r = try score(assertion[0]);
        try testing.expectEqual(assertion[1], r.score);
        try testing.expectEqual(assertion[2], r.level);
    }
}
