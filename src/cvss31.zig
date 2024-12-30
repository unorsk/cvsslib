const std = @import("std");
const types = @import("./types.zig");
const testing = std.testing;

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

pub const Cvss31MetricDecl = struct {
    isRead: bool,
    metricType: Cvss31MetricType,
    metricTypeValue: []const u8,
    required: bool,
    possibleValues: []const []const u8,
};

pub const Cvss31Metric = struct {
    metricType: Cvss31MetricType,
    value: []const u8,
};

// zig fmt: off
pub const Cvss31Decl: []const Cvss31MetricDecl = &.{
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

pub fn score(cvss: []const u8) !types.CVSS {
    const metrics = try parse_cvss31_metrics(cvss);
    return try score_cvss31(metrics);
}

fn score_cvss31(cvss_metrics: []types.Cvss31Metric) !types.CVSS {
    std.log.debug("metrics", .{cvss_metrics});
    return types.CVSS{ .CVSS31 = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
}

fn parse_cvss31_metrics(cvss: []const u8) ![]Cvss31Metric {
    var metrics = std.ArrayList(Cvss31Metric).init(std.heap.page_allocator);

    const copyCvss31Decl = try std.heap.page_allocator.dupe(Cvss31MetricDecl, Cvss31Decl);
    defer std.heap.page_allocator.free(copyCvss31Decl);

    var it = std.mem.tokenizeScalar(u8, cvss, '/');
    while (it.next()) |pair| {
        var itMetric = std.mem.tokenizeScalar(u8, pair, ':');
        const metricTypeRaw = itMetric.next();
        if (metricTypeRaw == null) {
            return types.CvssParseError.NotCVSSString;
        }

        var metricType: ?Cvss31MetricType = null;
        for (copyCvss31Decl) |*decl| {
            if (std.mem.eql(u8, metricTypeRaw.?, decl.metricTypeValue)) {
                if (decl.isRead == true) {
                    return types.CvssParseError.DuplicateMetric;
                }
                metricType = decl.metricType;
                decl.*.isRead = true;

                const metricValueRaw = itMetric.rest();

                var metricValue: ?[]const u8 = null;
                for (0..(decl.possibleValues.len)) |j| {
                    if (std.mem.eql(u8, metricValueRaw, decl.possibleValues[j])) {
                        metricValue = decl.possibleValues[j];
                        try metrics.append(.{ .metricType = metricType.?, .value = metricValue.? });
                        break;
                    }
                }
                if (metricValue == null) {
                    // std.debug.print("metric raw: {s}\n", .{metricValueRaw});
                    // std.debug.print("metric type: {}\n", .{metricType.?});
                    // std.debug.print("token: {s}\n", .{pair});
                    return types.CvssParseError.UnknownMetricValue;
                }

                break;
            }
        }
        if (metricType == null) {
            return types.CvssParseError.UnknownMetricName;
        }
    }

    for (copyCvss31Decl) |decl| {
        if (decl.required and !decl.isRead) {
            return types.CvssParseError.MissingRequiredMetrics;
        }
    }

    return metrics.items;
}

test "parse duplicate metric CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N";
    const err = parse_cvss31_metrics(cvss);
    try testing.expectError(types.CvssParseError.DuplicateMetric, err);
}

test "parse CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const metrics = try parse_cvss31_metrics(cvss);
    try testing.expectEqual(8, metrics.len);
    try testing.expectEqual(Cvss31MetricType.AV, metrics[0].metricType);
    try testing.expectEqual("N", metrics[0].value);
    try testing.expectEqual(Cvss31MetricType.AC, metrics[1].metricType);
    try testing.expectEqual("L", metrics[1].value);
    try testing.expectEqual(Cvss31MetricType.PR, metrics[2].metricType);
    try testing.expectEqual("L", metrics[2].value);
    try testing.expectEqual(Cvss31MetricType.UI, metrics[3].metricType);
    try testing.expectEqual("N", metrics[3].value);
    try testing.expectEqual(Cvss31MetricType.S, metrics[4].metricType);
    try testing.expectEqual("U", metrics[4].value);
    try testing.expectEqual(Cvss31MetricType.C, metrics[5].metricType);
    try testing.expectEqual("H", metrics[5].value);
    try testing.expectEqual(Cvss31MetricType.I, metrics[6].metricType);
    try testing.expectEqual("H", metrics[6].value);
    try testing.expectEqual(Cvss31MetricType.A, metrics[7].metricType);
    try testing.expectEqual("H", metrics[7].value);
}

test "parse simple AV metric unknown value" {
    const cvss = "AV:Z";
    const err = parse_cvss31_metrics(cvss);
    try testing.expectError(types.CvssParseError.UnknownMetricValue, err);
}
