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
    weights: []const f16,
    possibleValues: []const []const u8,
};

pub const Cvss31Metric = struct {
    metricType: Cvss31MetricType,
    value: []const u8,
    weight: f16,
};

// zig fmt: off
pub const Cvss31Decl: []const Cvss31MetricDecl = &.{
    .{ .isRead = false, .metricType = Cvss31MetricType.AV,  .metricTypeValue = "AV",  .required = true,  .weights = &.{0.85, 0.62, 0.55, 0.2},  .possibleValues = &.{ "N", "A", "L", "P" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.AC,  .metricTypeValue = "AC",  .required = true,  .weights = &.{0.44, 0.77},             .possibleValues = &.{ "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.PR,  .metricTypeValue = "PR",  .required = true,  .weights = &.{0, 0, 0},                .possibleValues = &.{ "N", "L", "H" } },// TODO &.{0, 0, 0}
    .{ .isRead = false, .metricType = Cvss31MetricType.UI,  .metricTypeValue = "UI",  .required = true,  .weights = &.{0.85, 0.62},             .possibleValues = &.{ "N", "R" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.S,   .metricTypeValue = "S",   .required = true,  .weights = &.{6.42, 7.52},             .possibleValues = &.{ "U", "C" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.C,   .metricTypeValue = "C",   .required = true,  .weights = &.{0, 0.22, 0.56},          .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.I,   .metricTypeValue = "I",   .required = true,  .weights = &.{0, 0.22, 0.56},          .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.A,   .metricTypeValue = "A",   .required = true,  .weights = &.{0, 0.22, 0.56},          .possibleValues = &.{ "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.E,   .metricTypeValue = "E",   .required = false, .weights = &.{1, 0.91, 0.94, 0.97, 1}, .possibleValues = &.{ "X", "U", "P", "F", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.RL,  .metricTypeValue = "RL",  .required = false, .weights = &.{1, 0.95, 0.96, 0.97, 1}, .possibleValues = &.{ "X", "O", "T", "W", "U", "P", "C", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.RC,  .metricTypeValue = "RC",  .required = false, .weights = &.{1, 0.92, 0.96, 1},       .possibleValues = &.{ "X", "U", "R", "C", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.CR,  .metricTypeValue = "CR",  .required = false, .weights = &.{1, 0.5, 1, 1.5},         .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.IR,  .metricTypeValue = "IR",  .required = false, .weights = &.{1, 0.5, 1, 1.5},         .possibleValues = &.{ "X", "L", "M", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.AR,  .metricTypeValue = "AR",  .required = false, .weights = &.{1, 0.5, 1, 1.5},         .possibleValues = &.{ "X", "L", "" } },

    .{ .isRead = false, .metricType = Cvss31MetricType.MAV, .metricTypeValue = "MAV", .required = false, .weights = &.{0, 0.85, 0.62, 0.55, 0.2},   .possibleValues = &.{ "X", "N", "A", "L", "P" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MAC, .metricTypeValue = "MAC", .required = false, .weights = &.{0, 0.44, 0.77},              .possibleValues = &.{ "X", "H", "L" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MPR, .metricTypeValue = "MPR", .required = false, .weights = &.{0, 0, 0, 0},                 .possibleValues = &.{ "X", "N", "L", "H" } }, // TODO &.{0, 0, 0}
    .{ .isRead = false, .metricType = Cvss31MetricType.MUI, .metricTypeValue = "MUI", .required = false, .weights = &.{0, 0.85, 0.62},              .possibleValues = &.{ "X", "N", "R" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MS,  .metricTypeValue = "MS",  .required = false, .weights = &.{0, 6.42, 7.52},              .possibleValues = &.{ "X", "U", "C" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MC,  .metricTypeValue = "MC",  .required = false, .weights = &.{0, 0, 0.22, 0.56},           .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MI,  .metricTypeValue = "MI",  .required = false, .weights = &.{0, 0, 0.22, 0.56},           .possibleValues = &.{ "X", "N", "L", "H" } },
    .{ .isRead = false, .metricType = Cvss31MetricType.MA,  .metricTypeValue = "MA",  .required = false, .weights = &.{0, 0, 0.22, 0.56},           .possibleValues = &.{ "X", "N", "L", "H" } },
};
// zig fmt: on

pub fn score(cvss: []const u8) !types.CVSS {
    const metrics = try parse_cvss31_metrics(cvss);
    return try score_cvss31(metrics);
}

fn score_cvss31(cvss_metrics: []Cvss31Metric) !types.CVSS {
    std.log.debug("metrics {any}", .{cvss_metrics});

    // TODO scoring

    //     var AV = AttackVector;
    //     var AC = AttackComplexity;
    //     var PR = PrivilegesRequired;
    //     var UI = UserInteraction;
    //     var S  = Scope;
    //     var C  = Confidentiality;
    //     var I  = Integrity;
    //     var A  = Availability;

    //     var E =   ExploitCodeMaturity || "X";
    //     var RL =  RemediationLevel    || "X";
    //     var RC =  ReportConfidence    || "X";

    //     var CR =  ConfidentialityRequirement || "X";
    //     var IR =  IntegrityRequirement       || "X";
    //     var AR =  AvailabilityRequirement    || "X";
    //     var MAV = ModifiedAttackVector       || "X";
    //     var MAC = ModifiedAttackComplexity   || "X";
    //     var MPR = ModifiedPrivilegesRequired || "X";
    //     var MUI = ModifiedUserInteraction    || "X";
    //     var MS =  ModifiedScope              || "X";
    //     var MC =  ModifiedConfidentiality    || "X";
    //     var MI =  ModifiedIntegrity          || "X";
    //     var MA =  ModifiedAvailability       || "X";

    // // WEIGHTS
    //     var metricWeightAV  = CVSS31.Weight.AV    [AV];
    //     var metricWeightAC  = CVSS31.Weight.AC    [AC];
    //     var metricWeightPR  = CVSS31.Weight.PR    [S][PR];  // PR depends on the value of Scope (S).
    //     var metricWeightUI  = CVSS31.Weight.UI    [UI];
    //     var metricWeightS   = CVSS31.Weight.S     [S];
    //     var metricWeightC   = CVSS31.Weight.CIA   [C];
    //     var metricWeightI   = CVSS31.Weight.CIA   [I];
    //     var metricWeightA   = CVSS31.Weight.CIA   [A];

    //     var metricWeightE   = CVSS31.Weight.E     [E];
    //     var metricWeightRL  = CVSS31.Weight.RL    [RL];
    //     var metricWeightRC  = CVSS31.Weight.RC    [RC];

    //     // For metrics that are modified versions of Base Score metrics, e.g. Modified Attack Vector, use the value of
    //     // the Base Score metric if the modified version value is "X" ("Not Defined").
    //     var metricWeightCR  = CVSS31.Weight.CIAR  [CR];
    //     var metricWeightIR  = CVSS31.Weight.CIAR  [IR];
    //     var metricWeightAR  = CVSS31.Weight.CIAR  [AR];
    //     var metricWeightMAV = CVSS31.Weight.AV    [MAV !== "X" ? MAV : AV];
    //     var metricWeightMAC = CVSS31.Weight.AC    [MAC !== "X" ? MAC : AC];
    //     var metricWeightMPR = CVSS31.Weight.PR    [MS  !== "X" ? MS  : S] [MPR !== "X" ? MPR : PR];  // Depends on MS.
    //     var metricWeightMUI = CVSS31.Weight.UI    [MUI !== "X" ? MUI : UI];
    //     var metricWeightMS  = CVSS31.Weight.S     [MS  !== "X" ? MS  : S];
    //     var metricWeightMC  = CVSS31.Weight.CIA   [MC  !== "X" ? MC  : C];
    //     var metricWeightMI  = CVSS31.Weight.CIA   [MI  !== "X" ? MI  : I];
    //     var metricWeightMA  = CVSS31.Weight.CIA   [MA  !== "X" ? MA  : A];

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
                        try metrics.append(.{ .metricType = metricType.?, .value = metricValue.?, .weight = decl.weights[j] });
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

test "parse missing metricCVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H";
    const err = parse_cvss31_metrics(cvss);
    try testing.expectError(types.CvssParseError.MissingRequiredMetrics, err);
}

test "parse green test CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
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
