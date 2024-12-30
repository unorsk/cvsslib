const types = @import("types.zig");
const std = @import("std");
const cvss31 = @import("./cvss31.zig");
const testing = std.testing;

const CVSS20_HEADER = "CVSS:2.0";
const CVSS30_HEADER = "CVSS:3.0";
const CVSS31_HEADER = "CVSS:3.1";
const CVSS40_HEADER = "CVSS:4.0";

pub fn cvss_score(cvss: []const u8) !types.CVSS {
    const version = try detect_cvss_version(cvss);
    switch (version) {
        types.CVSS_VERSION.CVSS20 => {
            return types.CVSS{ .CVSS20 = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
        types.CVSS_VERSION.CVSS30 => {
            return types.CVSS{ .CVSS30 = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
        types.CVSS_VERSION.CVSS31 => {
            return try cvss31.score(cvss[CVSS31_HEADER.len..]);
        },
        types.CVSS_VERSION.CVSS40 => {
            return types.CVSS{ .CVSS40 = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
    }
}

fn detect_cvss_version(cvss: []const u8) types.CvssParseError!types.CVSS_VERSION {
    std.debug.print("\n\n{s}\n\n", .{cvss});
    if (std.mem.eql(u8, cvss, CVSS20_HEADER)) {
        return types.CVSS_VERSION.CVSS20;
    } else if (std.mem.eql(u8, cvss, CVSS30_HEADER)) {
        return types.CVSS_VERSION.CVSS30;
    } else if (std.mem.eql(u8, cvss[0..CVSS31_HEADER.len], CVSS31_HEADER)) {
        return types.CVSS_VERSION.CVSS31;
    } else if (std.mem.eql(u8, cvss, CVSS40_HEADER)) {
        return types.CVSS_VERSION.CVSS40;
    } else {
        return types.CvssParseError.NotCVSSString;
    }
}

test "detect_cvss_version" {
    try testing.expect(try detect_cvss_version("CVSS:2.0") == types.CVSS_VERSION.CVSS20);
    try testing.expect(try detect_cvss_version("CVSS:3.0") == types.CVSS_VERSION.CVSS30);
    try testing.expect(try detect_cvss_version("CVSS:3.1") == types.CVSS_VERSION.CVSS31);
    try testing.expect(try detect_cvss_version("CVSS:4.0") == types.CVSS_VERSION.CVSS40);

    _ = detect_cvss_version("CVSS:5.0") catch |err| {
        try testing.expect(err == types.CvssParseError.NotCVSSString);
    };

    _ = detect_cvss_version("") catch |err| {
        try testing.expect(err == types.CvssParseError.NotCVSSString);
    };

    _ = detect_cvss_version(" ") catch |err| {
        try testing.expect(err == types.CvssParseError.NotCVSSString);
    };
}
