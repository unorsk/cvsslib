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
    isRead: bool,
    metricType: Cvss31MetricType,
    metricTypeValue: []const u8,
    required: bool,
    possibleValues: []const []const u8,
};

const Cvss31Metric = struct {
    metricType: Cvss31MetricType,
    value: []const u8,
};

const CvssParseError = error{
    NotCVSSString,
    UnknownMetricValue,
};

// zig fmt: off
const Cvss31Decl: []const Cvss31MetricDecl = &.{
    .{ .isRead = false, .metricType = Cvss31MetricType.AV,  .metricTypeValue = "AV",  .required = true,  .possibleValues = &.{ "N", "A", "L", "P" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.AC,  .metricTypeValue = "AC",  .required = true,  .possibleValues = &.{ "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.PR,  .metricTypeValue = "PR",  .required = true,  .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.UI,  .metricTypeValue = "UI",  .required = true,  .possibleValues = &.{ "N", "R" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.S,   .metricTypeValue = "S",   .required = true,  .possibleValues = &.{ "U", "C" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.C,   .metricTypeValue = "C",   .required = true,  .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.I,   .metricTypeValue = "I",   .required = true,  .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.A,   .metricTypeValue = "A",   .required = true,  .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.E,   .metricTypeValue = "E",   .required = false, .possibleValues = &.{ "X", "U", "P", "F", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.RL,  .metricTypeValue = "RL",  .required = false, .possibleValues = &.{ "X", "O", "T", "W", "U", "P", "C", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.RC,  .metricTypeValue = "RC",  .required = false, .possibleValues = &.{ "X", "U", "R", "C", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.CR,  .metricTypeValue = "CR",  .required = false, .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.IR,  .metricTypeValue = "IR",  .required = false, .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.AR,  .metricTypeValue = "AR",  .required = false, .possibleValues = &.{ "X", "L", "" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MAV, .metricTypeValue = "MAV", .required = false, .possibleValues = &.{ "X", "N", "A", "L", "P" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MAC, .metricTypeValue = "MAC", .required = false, .possibleValues = &.{ "X", "H", "L" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MPR, .metricTypeValue = "MPR", .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MUI, .metricTypeValue = "MUI", .required = false, .possibleValues = &.{ "X", "N", "R" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MS,  .metricTypeValue = "MS",  .required = false, .possibleValues = &.{ "X", "U", "C" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MC,  .metricTypeValue = "MC",  .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MI,  .metricTypeValue = "MI",  .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MA,  .metricTypeValue = "MA",  .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
};
// zig fmt: on

fn eql(comptime T: type, a: []const T, b: []const T, i: usize) bool {
    return std.mem.eql(T, a[i..(i + b.len)], b);
}

fn parse_cvss31_metrics(cvss: []const u8) ![]Cvss31Metric {
    var metrics = std.ArrayList(Cvss31Metric).init(std.heap.page_allocator);

    var it = std.mem.tokenizeScalar(u8, cvss, ' ');
    while (it.next()) |token| {
        std.debug.print("token: {s}\n", .{token});
        var itMetric = std.mem.tokenizeScalar(u8, token, ':');
        const metricType = itMetric.next();
        if (metricType == null) {
            return CvssParseError.NotCVSSString;
        }
        std.debug.print("metricType: {s}\n", .{metricType.?});
        const metricValue = itMetric.rest();
        std.debug.print("metricValue: {s}\n", .{metricValue});
    }

    var i: usize = 0;
    while (i < cvss.len) {
        var metricType: ?Cvss31MetricType = null;
        for (Cvss31Decl) |decl| {
            if (eql(u8, cvss, decl.metricTypeValue, i)) {
                metricType = decl.metricType;
                i += decl.metricTypeValue.len;
                // todo read the colon
                i += 1; // skip the colon

                var value: ?[]const u8 = null;
                for (0..(decl.possibleValues.len - 1)) |j| {
                    if (eql(u8, cvss, decl.possibleValues[j], i)) {
                        value = decl.possibleValues[j];
                        try metrics.append(.{ .metricType = metricType.?, .value = value.? });
                        i += value.?.len;
                        break;
                    }
                }
                if (value == null) {
                    return CvssParseError.UnknownMetricValue;
                }
                break;
            }
        }

        if (metricType == null) {
            return CvssParseError.NotCVSSString;
        }

        // todo consume "/"
        i += 1;
        // i += value.len;
    }

    return metrics.items;
}

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

test "parse simple AV metric" {
    const cvss = "AV:N";
    const metrics = try parse_cvss31_metrics(cvss);
    std.debug.print("size: {}\n", .{metrics.len});
    try testing.expect(metrics.len == 1);
    try testing.expect(metrics[0].metricType == Cvss31MetricType.AV);
    try testing.expect(std.mem.eql(u8, metrics[0].value, "N"));
}

test "parse simple AV metric unknown value" {
    const cvss = "AV:Z";
    const err = parse_cvss31_metrics(cvss);
    try testing.expectError(CvssParseError.UnknownMetricValue, err);
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
