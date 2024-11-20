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

const Cvss31MetricType = enum {
    AV,
    AC,
    PR,
    UI,
    S,
    C,
    I,
    A,
    E,
    RL,
    RC,
    CR,
    IR,
    AR,
    MAV,
    MAC,
    MPR,
    MUI,
    MS,
    MC,
    MI,
    MA,
};

const Cvss31MetricDecl = struct {
    metricType: Cvss31MetricType,
    required: bool,
    possibleValues: []const []const u8,
};

const Cvss31Metric = struct {
    metricType: Cvss31MetricType,
    value: []const u8,
};

const CvssParseError = error{
    NotCVSSString,
};

const Cvss31Decl: []const Cvss31MetricDecl = &.{
    .{ .metricType = Cvss31MetricType.AV, .required = true, .possibleValues = &.{ "N", "A", "L", "P" } },
    .{ .metricType = Cvss31MetricType.AC, .required = true, .possibleValues = &.{ "L", "H" } },
    .{ .metricType = Cvss31MetricType.PR, .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.UI, .required = true, .possibleValues = &.{ "N", "R" } },
    .{ .metricType = Cvss31MetricType.S, .required = true, .possibleValues = &.{ "U", "C" } },
    .{ .metricType = Cvss31MetricType.C, .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.I, .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.A, .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.E, .required = false, .possibleValues = &.{ "X", "U", "P", "F", "H" } },
    .{ .metricType = Cvss31MetricType.RL, .required = false, .possibleValues = &.{ "X", "O", "T", "W", "U", "P", "C", "H" } },
    .{ .metricType = Cvss31MetricType.RC, .required = false, .possibleValues = &.{ "X", "U", "R", "C", "H" } },
    .{ .metricType = Cvss31MetricType.CR, .required = false, .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .metricType = Cvss31MetricType.IR, .required = false, .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .metricType = Cvss31MetricType.AR, .required = false, .possibleValues = &.{ "X", "L", "" } },
    .{ .metricType = Cvss31MetricType.MAV, .required = false, .possibleValues = &.{ "X", "N", "A", "L", "P" } },
    .{ .metricType = Cvss31MetricType.MAC, .required = false, .possibleValues = &.{ "X", "H", "L" } },
    .{ .metricType = Cvss31MetricType.MPR, .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.MUI, .required = false, .possibleValues = &.{ "X", "N", "R" } },
    .{ .metricType = Cvss31MetricType.MS, .required = false, .possibleValues = &.{ "X", "U", "C" } },
    .{ .metricType = Cvss31MetricType.MC, .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.MI, .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.MA, .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
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
