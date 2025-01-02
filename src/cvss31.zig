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

pub const Cvss31MetricDef = struct {
    is_read: bool = false,
    metric_type: Cvss31MetricType,
    value: []const u8,
    required: bool,
    weights: []const f16,
    constraints: []const []const u8,
};

pub const Cvss31Metric = struct {
    metric_type: Cvss31MetricType,
    value: []const u8,
    weight: f16,
};

// TODO pass by reference
fn getMetric(metric: Cvss31MetricType, cvss_metrics: []Cvss31Metric) ?Cvss31Metric {
    for (cvss_metrics) |cvss_metric| {
        if (metric == cvss_metric.metric_type) {
            return cvss_metric;
        }
    }
    return null;
}

// TODO pass by reference
fn getMetricWeight(metric: Cvss31MetricType, cvss_metrics: []Cvss31Metric) f16 {
    std.log.debug("{any}", .{cvss_metrics});
    const metric_value = getMetric(metric, cvss_metrics);
    return switch (metric) {
        Cvss31MetricType.AV => metric_value.?.weight,
        Cvss31MetricType.AC => 0,
        Cvss31MetricType.PR => 0,
        Cvss31MetricType.UI => 0,
        Cvss31MetricType.S => 0,
        Cvss31MetricType.C => 0,
        Cvss31MetricType.I => 0,
        Cvss31MetricType.A => 0,
        Cvss31MetricType.E => 0,
        Cvss31MetricType.RL => 0,
        Cvss31MetricType.RC => 0,
        Cvss31MetricType.CR => 0,
        Cvss31MetricType.IR => 0,
        Cvss31MetricType.AR => 0,
        Cvss31MetricType.MAV => 0,
        Cvss31MetricType.MAC => 0,
        Cvss31MetricType.MPR => 0,
        Cvss31MetricType.MUI => 0,
        Cvss31MetricType.MS => 0,
        Cvss31MetricType.MC => 0,
        Cvss31MetricType.MI => 0,
        Cvss31MetricType.MA => 0,
    };
}

// zig fmt: off
pub const cvss31_definitions: []const Cvss31MetricDef = &.{
    .{ .metric_type = Cvss31MetricType.AV,  .value = "AV",  .required = true,  .weights = &.{0.85, 0.62, 0.55, 0.2},  .constraints = &.{ "N", "A", "L", "P" } },
    .{ .metric_type = Cvss31MetricType.AC,  .value = "AC",  .required = true,  .weights = &.{0.44, 0.77},             .constraints = &.{ "L", "H" } },
    .{ .metric_type = Cvss31MetricType.PR,  .value = "PR",  .required = true,  .weights = &.{0.85, 0.62, 0.27,
                                                                                             0.85, 0.68, 0.5},        .constraints = &.{ "N", "L", "H" } },// TODO &.{0, 0, 0}
    .{ .metric_type = Cvss31MetricType.UI,  .value = "UI",  .required = true,  .weights = &.{0.85, 0.62},             .constraints = &.{ "N", "R" } },
    .{ .metric_type = Cvss31MetricType.S,   .value = "S",   .required = true,  .weights = &.{6.42, 7.52},             .constraints = &.{ "U", "C" } },
    .{ .metric_type = Cvss31MetricType.C,   .value = "C",   .required = true,  .weights = &.{0, 0.22, 0.56},          .constraints = &.{ "N", "L", "H" } },
    .{ .metric_type = Cvss31MetricType.I,   .value = "I",   .required = true,  .weights = &.{0, 0.22, 0.56},          .constraints = &.{ "N", "L", "H" } },
    .{ .metric_type = Cvss31MetricType.A,   .value = "A",   .required = true,  .weights = &.{0, 0.22, 0.56},          .constraints = &.{ "N", "L", "H" } },
    .{ .metric_type = Cvss31MetricType.E,   .value = "E",   .required = false, .weights = &.{1, 0.91, 0.94, 0.97, 1}, .constraints = &.{ "X", "U", "P", "F", "H" } },
    .{ .metric_type = Cvss31MetricType.RL,  .value = "RL",  .required = false, .weights = &.{1, 0.95, 0.96, 0.97, 1}, .constraints = &.{ "X", "O", "T", "W", "U", "P", "C", "H" } },
    .{ .metric_type = Cvss31MetricType.RC,  .value = "RC",  .required = false, .weights = &.{1, 0.92, 0.96, 1},       .constraints = &.{ "X", "U", "R", "C", "H" } },
    .{ .metric_type = Cvss31MetricType.CR,  .value = "CR",  .required = false, .weights = &.{1, 0.5, 1, 1.5},         .constraints = &.{ "X", "L", "M", "H" } },
    .{ .metric_type = Cvss31MetricType.IR,  .value = "IR",  .required = false, .weights = &.{1, 0.5, 1, 1.5},         .constraints = &.{ "X", "L", "M", "H" } },
    .{ .metric_type = Cvss31MetricType.AR,  .value = "AR",  .required = false, .weights = &.{1, 0.5, 1, 1.5},         .constraints = &.{ "X", "L", "" } },

    .{ .metric_type = Cvss31MetricType.MAV, .value = "MAV", .required = false, .weights = &.{0, 0.85, 0.62, 0.55, 0.2},   .constraints = &.{ "X", "N", "A", "L", "P" } },
    .{ .metric_type = Cvss31MetricType.MAC, .value = "MAC", .required = false, .weights = &.{0, 0.44, 0.77},              .constraints = &.{ "X", "H", "L" } },
    .{ .metric_type = Cvss31MetricType.MPR, .value = "MPR", .required = false, .weights = &.{0.85, 0.62, 0.27,
                                                                                             0.85, 0.68, 0.5},            .constraints = &.{ "X", "N", "L", "H" } }, // TODO &.{0, 0, 0}
    .{ .metric_type = Cvss31MetricType.MUI, .value = "MUI", .required = false, .weights = &.{0, 0.85, 0.62},              .constraints = &.{ "X", "N", "R" } },
    .{ .metric_type = Cvss31MetricType.MS,  .value = "MS",  .required = false, .weights = &.{0, 6.42, 7.52},              .constraints = &.{ "X", "U", "C" } },
    .{ .metric_type = Cvss31MetricType.MC,  .value = "MC",  .required = false, .weights = &.{0, 0, 0.22, 0.56},           .constraints = &.{ "X", "N", "L", "H" } },
    .{ .metric_type = Cvss31MetricType.MI,  .value = "MI",  .required = false, .weights = &.{0, 0, 0.22, 0.56},           .constraints = &.{ "X", "N", "L", "H" } },
    .{ .metric_type = Cvss31MetricType.MA,  .value = "MA",  .required = false, .weights = &.{0, 0, 0.22, 0.56},           .constraints = &.{ "X", "N", "L", "H" } },
};
// zig fmt: on

pub fn score(cvss: []const u8) !types.CVSS {
    const metrics = try parseCvss31Metrics(cvss);
    return try scoreCvss31(metrics);
}

// TODO pass by reference
fn scoreCvss31(cvss_metrics: []Cvss31Metric) !types.CVSS {
    std.log.debug("metrics {any}", .{cvss_metrics});

    // TODO scoring

    const av = getMetricWeight(Cvss31MetricType.AV, cvss_metrics);
    std.log.debug("{any}", .{av});
    return types.CVSS{ .CVSS31 = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
}

fn parseCvss31Metrics(cvss: []const u8) ![]Cvss31Metric {
    var metrics = std.ArrayList(Cvss31Metric).init(std.heap.page_allocator);

    const copy_cvss31_def = try std.heap.page_allocator.dupe(Cvss31MetricDef, cvss31_definitions);
    defer std.heap.page_allocator.free(copy_cvss31_def);

    var it = std.mem.tokenizeScalar(u8, cvss, '/');
    while (it.next()) |pair| {
        var it_metric = std.mem.tokenizeScalar(u8, pair, ':');
        const metric_type_raw = it_metric.next();
        if (metric_type_raw == null) {
            return types.CvssParseError.NotCVSSString;
        }

        var metric_type: ?Cvss31MetricType = null;
        for (copy_cvss31_def) |*decl| {
            if (std.mem.eql(u8, metric_type_raw.?, decl.value)) {
                if (decl.is_read == true) {
                    return types.CvssParseError.DuplicateMetric;
                }
                metric_type = decl.metric_type;
                decl.*.is_read = true;

                const metric_value_raw = it_metric.rest();

                var metric_value: ?[]const u8 = null;
                for (0..(decl.constraints.len)) |j| {
                    if (std.mem.eql(u8, metric_value_raw, decl.constraints[j])) {
                        metric_value = decl.constraints[j];
                        try metrics.append(.{ .metric_type = metric_type.?, .value = metric_value.?, .weight = decl.weights[j] });
                        break;
                    }
                }
                if (metric_value == null) {
                    // std.debug.print("metric raw: {s}\n", .{metricValueRaw});
                    // std.debug.print("metric type: {}\n", .{metricType.?});
                    // std.debug.print("token: {s}\n", .{pair});
                    return types.CvssParseError.UnknownMetricValue;
                }

                break;
            }
        }
        if (metric_type == null) {
            return types.CvssParseError.UnknownMetricName;
        }
    }

    for (copy_cvss31_def) |decl| {
        if (decl.required and !decl.is_read) {
            return types.CvssParseError.MissingRequiredMetrics;
        }
    }

    return metrics.items; // TODO what happens to the slice when the allocator frees the memory?
}

test "parse duplicate metric CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N";
    const err = parseCvss31Metrics(cvss);
    try testing.expectError(types.CvssParseError.DuplicateMetric, err);
}

test "parse missing metricCVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H";
    const err = parseCvss31Metrics(cvss);
    try testing.expectError(types.CvssParseError.MissingRequiredMetrics, err);
}

test "parse green test CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const metrics = try parseCvss31Metrics(cvss);
    try testing.expectEqual(8, metrics.len);
    try testing.expectEqual(Cvss31MetricType.AV, metrics[0].metric_type);
    try testing.expectEqual("N", metrics[0].value);
    try testing.expectEqual(Cvss31MetricType.AC, metrics[1].metric_type);
    try testing.expectEqual("L", metrics[1].value);
    try testing.expectEqual(Cvss31MetricType.PR, metrics[2].metric_type);
    try testing.expectEqual("L", metrics[2].value);
    try testing.expectEqual(Cvss31MetricType.UI, metrics[3].metric_type);
    try testing.expectEqual("N", metrics[3].value);
    try testing.expectEqual(Cvss31MetricType.S, metrics[4].metric_type);
    try testing.expectEqual("U", metrics[4].value);
    try testing.expectEqual(Cvss31MetricType.C, metrics[5].metric_type);
    try testing.expectEqual("H", metrics[5].value);
    try testing.expectEqual(Cvss31MetricType.I, metrics[6].metric_type);
    try testing.expectEqual("H", metrics[6].value);
    try testing.expectEqual(Cvss31MetricType.A, metrics[7].metric_type);
    try testing.expectEqual("H", metrics[7].value);
}

test "parse simple AV metric unknown value" {
    const cvss = "AV:Z";
    const err = parseCvss31Metrics(cvss);
    try testing.expectError(types.CvssParseError.UnknownMetricValue, err);
}
