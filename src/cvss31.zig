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

// zig fmt: off
const Cvss31MetricTypeValue = union(Cvss31MetricType) {
    AV:  enum { N, A, L, P },
    AC:  enum { L, H },
    PR:  enum { N, L, H },
    UI:  enum { N, R },
    S:   enum { U, C },
    C:   enum { N, L, H },
    I:   enum { N, L, H },
    A:   enum { N, L, H },
    E:   enum { X, U, P, F, H },
    RL:  enum { X, O, T, W, U, P, C, H },
    RC:  enum { X, U, R, C, H },
    CR:  enum { X, L, M, H },
    IR:  enum { X, L, M, H },
    AR:  enum { X, L, M, H },
    MAV: enum { X, N, A, L, P },
    MAC: enum { X, H, L },
    MPR: enum { X, N, L, H },
    MUI: enum { X, N, R },
    MS:  enum { X, U, C },
    MC:  enum { X, N, L, H },
    MI:  enum { X, N, L, H },
    MA:  enum { X, N, L, H },
};
// zig fmt: on

pub const Cvss31MetricDef = struct {
    is_read: bool = false,
    metric_type: Cvss31MetricType,
    required: bool,
    weights: []const f16,
};

pub const Cvss31Metric = struct {
    value: Cvss31MetricTypeValue,
    test_metric_type: if (@import("builtin").mode == .Debug) Cvss31MetricType else void = undefined, // TODO I no longer need this one, but I could use
    test_value: if (@import("builtin").mode == .Debug) []const u8 else void = undefined,
    // weight: f16,
};

// TODO pass by reference
fn getMetric(metric: Cvss31MetricType, cvss_metrics: []Cvss31Metric) ?Cvss31Metric {
    for (cvss_metrics) |cvss_metric| {
        if (metric == cvss_metric.test_metric_type) {
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
        Cvss31MetricType.AV => metric_value.?.value,
        Cvss31MetricType.AC => metric_value.?.weight,
        Cvss31MetricType.PR => {
            // if (getMetric(Cvss31MetricType.S, cvss_metrics)) |s| {
            //     if (s.value == 'S') {}
            // } else {}
            return 0;
        },
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
    .{ .metric_type = Cvss31MetricType.AV, .required = true,  .weights = &.{0.85, 0.62, 0.55, 0.2}},
    .{ .metric_type = Cvss31MetricType.AC, .required = true,  .weights = &.{0.44, 0.77}},
    .{ .metric_type = Cvss31MetricType.PR, .required = true,  .weights = &.{0.85, 0.62, 0.27,
                                                                            0.85, 0.68, 0.5}},// TODO &.{0, 0, 0}
    .{ .metric_type = Cvss31MetricType.UI, .required = true,  .weights = &.{0.85, 0.62}},
    .{ .metric_type = Cvss31MetricType.S,  .required = true,  .weights = &.{6.42, 7.52}},
    .{ .metric_type = Cvss31MetricType.C,  .required = true,  .weights = &.{0, 0.22, 0.56}},
    .{ .metric_type = Cvss31MetricType.I,  .required = true,  .weights = &.{0, 0.22, 0.56}},
    .{ .metric_type = Cvss31MetricType.A,  .required = true,  .weights = &.{0, 0.22, 0.56}},
    .{ .metric_type = Cvss31MetricType.E,  .required = false, .weights = &.{1, 0.91, 0.94, 0.97, 1}},
    .{ .metric_type = Cvss31MetricType.RL, .required = false, .weights = &.{1, 0.95, 0.96, 0.97, 1}},
    .{ .metric_type = Cvss31MetricType.RC, .required = false, .weights = &.{1, 0.92, 0.96, 1}},
    .{ .metric_type = Cvss31MetricType.CR, .required = false, .weights = &.{1, 0.5, 1, 1.5}},
    .{ .metric_type = Cvss31MetricType.IR, .required = false, .weights = &.{1, 0.5, 1, 1.5}},
    .{ .metric_type = Cvss31MetricType.AR, .required = false, .weights = &.{1, 0.5, 1, 1.5}},

    .{ .metric_type = Cvss31MetricType.MAV, .required = false, .weights = &.{0, 0.85, 0.62, 0.55, 0.2}},
    .{ .metric_type = Cvss31MetricType.MAC, .required = false, .weights = &.{0, 0.44, 0.77}},
    .{ .metric_type = Cvss31MetricType.MPR, .required = false, .weights = &.{0.85, 0.62, 0.27,
                                                                             0.85, 0.68, 0.5}}, // TODO &.{0, 0, 0}
    .{ .metric_type = Cvss31MetricType.MUI, .required = false, .weights = &.{0, 0.85, 0.62}},
    .{ .metric_type = Cvss31MetricType.MS,  .required = false, .weights = &.{0, 6.42, 7.52}},
    .{ .metric_type = Cvss31MetricType.MC,  .required = false, .weights = &.{0, 0, 0.22, 0.56}},
    .{ .metric_type = Cvss31MetricType.MI,  .required = false, .weights = &.{0, 0, 0.22, 0.56}},
    .{ .metric_type = Cvss31MetricType.MA,  .required = false, .weights = &.{0, 0, 0.22, 0.56}},
};
// zig fmt: on

fn stringToEnum(enum_type: type, str: []const u8) ?enum_type {
    inline for (@typeInfo(enum_type).Enum.fields) |field| {
        if (std.mem.eql(u8, field.name, str)) {
            return @field(enum_type, field.name);
        }
    }
    return null;
}

fn createMetricValue(metric_type_str: []const u8, value_str: []const u8) ?Cvss31MetricTypeValue {
    inline for (@typeInfo(Cvss31MetricTypeValue).Union.fields) |field| {
        if (std.mem.eql(u8, field.name, metric_type_str)) {
            const FieldType = field.type;
            const enum_value = stringToEnum(FieldType, value_str) orelse return null;
            return @unionInit(Cvss31MetricTypeValue, field.name, enum_value);
        }
    }
    return null;
}

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
            const metric_name = @tagName(decl.metric_type);
            if (std.mem.eql(u8, metric_type_raw.?, metric_name)) {
                if (decl.is_read == true) {
                    return types.CvssParseError.DuplicateMetric;
                }
                metric_type = decl.metric_type;
                decl.*.is_read = true;

                const metric_value_raw = it_metric.rest();

                if (createMetricValue(metric_type_raw.?, metric_value_raw)) |metric_value| {
                    try metrics.append(.{ .test_metric_type = if (@import("builtin").mode == .Debug) metric_type.?, .value = metric_value, .test_value = if (@import("builtin").mode == .Debug) metric_value_raw });
                } else {
                    std.log.debug("Unexpected value {any}", .{metric_value_raw});
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
    try testing.expectEqual(Cvss31MetricType.AV, metrics[0].test_metric_type);
    try testing.expectEqualSlices(u8, "N", metrics[0].test_value);
    try testing.expectEqual(Cvss31MetricType.AC, metrics[1].test_metric_type);
    try testing.expectEqualSlices(u8, "L", metrics[1].test_value);
    try testing.expectEqual(Cvss31MetricType.PR, metrics[2].test_metric_type);
    try testing.expectEqualSlices(u8, "L", metrics[2].test_value);
    try testing.expectEqual(Cvss31MetricType.UI, metrics[3].test_metric_type);
    try testing.expectEqualSlices(u8, "N", metrics[3].test_value);
    try testing.expectEqual(Cvss31MetricType.S, metrics[4].test_metric_type);
    try testing.expectEqualSlices(u8, "U", metrics[4].test_value);
    try testing.expectEqual(Cvss31MetricType.C, metrics[5].test_metric_type);
    try testing.expectEqualSlices(u8, "H", metrics[5].test_value);
    try testing.expectEqual(Cvss31MetricType.I, metrics[6].test_metric_type);
    try testing.expectEqualSlices(u8, "H", metrics[6].test_value);
    try testing.expectEqual(Cvss31MetricType.A, metrics[7].test_metric_type);
    try testing.expectEqualSlices(u8, "H", metrics[7].test_value);
}

test "parse simple AV metric unknown value" {
    const cvss = "AV:Z";
    const err = parseCvss31Metrics(cvss);
    try testing.expectError(types.CvssParseError.UnknownMetricValue, err);
}
