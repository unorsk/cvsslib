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
    };

    for (assertions) |assertion| {
        const r = try score(assertion[0]);
        try testing.expectEqual(assertion[1], r.score);
        try testing.expectEqual(assertion[2], r.level);
    }
}
