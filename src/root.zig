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
};

const Cvss31Decl: []const Cvss31MetricDecl = &.{
    .{ .metricType = Cvss31MetricType.AV, .metricTypeValue = "AV", .required = true, .possibleValues = &.{ "N", "A", "L", "P" } },
    .{ .metricType = Cvss31MetricType.AC, .metricTypeValue = "AC", .required = true, .possibleValues = &.{ "L", "H" } },
    .{ .metricType = Cvss31MetricType.PR, .metricTypeValue = "PR", .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.UI, .metricTypeValue = "UI", .required = true, .possibleValues = &.{ "N", "R" } },
    .{ .metricType = Cvss31MetricType.S, .metricTypeValue = "S", .required = true, .possibleValues = &.{ "U", "C" } },
    .{ .metricType = Cvss31MetricType.C, .metricTypeValue = "C", .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.I, .metricTypeValue = "I", .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.A, .metricTypeValue = "A", .required = true, .possibleValues = &.{ "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.E, .metricTypeValue = "E", .required = false, .possibleValues = &.{ "X", "U", "P", "F", "H" } },
    .{ .metricType = Cvss31MetricType.RL, .metricTypeValue = "RL", .required = false, .possibleValues = &.{ "X", "O", "T", "W", "U", "P", "C", "H" } },
    .{ .metricType = Cvss31MetricType.RC, .metricTypeValue = "RC", .required = false, .possibleValues = &.{ "X", "U", "R", "C", "H" } },
    .{ .metricType = Cvss31MetricType.CR, .metricTypeValue = "CR", .required = false, .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .metricType = Cvss31MetricType.IR, .metricTypeValue = "IR", .required = false, .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .metricType = Cvss31MetricType.AR, .metricTypeValue = "AR", .required = false, .possibleValues = &.{ "X", "L", "" } },
    .{ .metricType = Cvss31MetricType.MAV, .metricTypeValue = "MAV", .required = false, .possibleValues = &.{ "X", "N", "A", "L", "P" } },
    .{ .metricType = Cvss31MetricType.MAC, .metricTypeValue = "MAC", .required = false, .possibleValues = &.{ "X", "H", "L" } },
    .{ .metricType = Cvss31MetricType.MPR, .metricTypeValue = "MPR", .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.MUI, .metricTypeValue = "MUI", .required = false, .possibleValues = &.{ "X", "N", "R" } },
    .{ .metricType = Cvss31MetricType.MS, .metricTypeValue = "MS", .required = false, .possibleValues = &.{ "X", "U", "C" } },
    .{ .metricType = Cvss31MetricType.MC, .metricTypeValue = "MC", .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.MI, .metricTypeValue = "MI", .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .metricType = Cvss31MetricType.MA, .metricTypeValue = "MA", .required = false, .possibleValues = &.{ "X", "N", "L", "H" } },
};

fn parse_cvss31_metrics(cvss: []const u8) ![]Cvss31Metric {
    // fn parse_cvss31_metrics(cvss: []const u8) !void {
    var metrics = std.ArrayList(Cvss31Metric).init(std.heap.page_allocator);
    // const metricsA = [_]Cvss31Metric{};

    var i: usize = 0;
    while (i < cvss.len) {
        // var metricType: Cvss31MetricType = undefined;

        for (Cvss31Decl) |decl| {
            if (std.mem.eql(u8, cvss[i..], decl.metricTypeValue)) {
                i += decl.metricTypeValue.len;
                i += 1; // skip the colon

                var value: []const u8 = undefined;
                for (0..(decl.possibleValues.len - 1)) |j| {
                    value = decl.possibleValues[j];
                    if (std.mem.eql(u8, cvss[i..], decl.possibleValues[j])) {
                        try metrics.append(.{ .metricType = decl.metricType, .value = value });
                        break;
                    }
                }
                // if (value == undefined) {
                //     return CvssParseError.NotCVSSString;
                // }
            }
        }

        // if (metricType == undefined) {
        //     return CvssParseError.NotCVSSString;
        // }

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

pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "parse simple AV metric" {
    const cvss = "AV:N";
    const metrics = try parse_cvss31_metrics(cvss);
    std.debug.print("size: {}\n", .{metrics.len});
    // std.debug.print("val {}\n", .{metrics[0].metricType});
    // std.debug.print("val {}\n", .{metrics[1].metricType});
    // std.debug.print("{}\n", .{metrics});
    try testing.expect(metrics.len == 1);
    try testing.expect(metrics[0].metricType == Cvss31MetricType.AV);
    try testing.expect(std.mem.eql(u8, metrics[0].value, "N"));
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
