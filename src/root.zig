const std = @import("std");
const testing = std.testing;

pub const CVSS_VERSION = enum {
    CVSS2,
    CVSS3,
    CVSS31,
    CVSS40,
};

pub const CVSS_LEVEL = enum {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
};

const CVSS20_HEADER = "CVSS:2.0";
const CVSS30_HEADER = "CVSS:3.0";
const CVSS31_HEADER = "CVSS:3.1";
const CVSS40_HEADER = "CVSS:4.0";

const CvssParseError = error{
    NotCVSSString,
};

fn detect_cvss_version(cvss: []const u8) CvssParseError!CVSS_VERSION {
    if (std.mem.eql(u8, cvss, CVSS20_HEADER)) {
        return CVSS_VERSION.CVSS2;
    } else if (std.mem.eql(u8, cvss, CVSS30_HEADER)) {
        return CVSS_VERSION.CVSS3;
    } else if (std.mem.eql(u8, cvss, CVSS31_HEADER)) {
        return CVSS_VERSION.CVSS31;
    } else if (std.mem.eql(u8, cvss, CVSS40_HEADER)) {
        return CVSS_VERSION.CVSS40;
    } else {
        return CvssParseError.NotCVSSString;
    }
}

pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "detect_cvss_version" {
    try testing.expect(try detect_cvss_version("CVSS:2.0") == CVSS_VERSION.CVSS2);
    try testing.expect(try detect_cvss_version("CVSS:3.0") == CVSS_VERSION.CVSS3);
    try testing.expect(try detect_cvss_version("CVSS:3.1") == CVSS_VERSION.CVSS31);
    try testing.expect(try detect_cvss_version("CVSS:4.0") == CVSS_VERSION.CVSS40);

    _ = detect_cvss_version("CVSS:5.0") catch |err| {
        try testing.expect(err == CvssParseError.NotCVSSString);
    };

    _ = detect_cvss_version("") catch |err| {
        try testing.expect(err == CvssParseError.NotCVSSString);
    };

    _ = detect_cvss_version(" ") catch |err| {
        try testing.expect(err == CvssParseError.NotCVSSString);
    };
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
