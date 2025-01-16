const std = @import("std");
const types = @import("./types.zig");
const util = @import("./util.zig");

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

pub const CVSS31 = struct {
    // Base Metric Group
    attack_vector: AttackVector,
    attack_complexity: AttackComplexity,
    privileges_required: PrivilegesRequired,
    user_interaction: UserInteraction,
    scope: Scope,
    confidentiality: Impact,
    integrity: Impact,
    availability: Impact,

    // Temporal Metric Group (optional)
    exploit_code_maturity: ?ExploitCodeMaturity = null,
    remediation_level: ?RemediationLevel = null,
    report_confidence: ?ReportConfidence = null,

    // Environmental Metric Group (optional)
    confidentiality_requirement: ?SecurityRequirement = null,
    integrity_requirement: ?SecurityRequirement = null,
    availability_requirement: ?SecurityRequirement = null,

    modified_attack_vector: ?AttackVector = null,
    modified_attack_complexity: ?AttackComplexity = null,
    modified_privileges_required: ?PrivilegesRequired = null,
    modified_user_interaction: ?UserInteraction = null,
    modified_scope: ?Scope = null,
    modified_confidentiality: ?Impact = null,
    modified_integrity: ?Impact = null,
    modified_availability: ?Impact = null,

    // pub fn calculateScore(self: CVSS31) f32 {
    //     // Implement CVSS 3.1 scoring algorithm here
    //     @compileError("Not implemented");
    // }

    // pub fn toVectorString(self: CVSS31, allocator: std.mem.Allocator) ![]const u8 {
    //     // Implement vector string generation here
    //     @compileError("Not implemented");
    // }

    // pub fn fromVectorString(allocator: std.mem.Allocator, vector: []const u8) !CVSS31 {
    //     // Implement parsing from vector string here
    //     @compileError("Not implemented");
    // }
};

pub const AttackVector = enum { Network, Adjacent, Local, Physical };
pub const AttackComplexity = enum { Low, High };
pub const PrivilegesRequired = enum { None, Low, High };
pub const UserInteraction = enum { None, Required };
pub const Scope = enum { Unchanged, Changed };
pub const Impact = enum { None, Low, High };
pub const ExploitCodeMaturity = enum { Unproven, ProofOfConcept, Functional, High };
pub const RemediationLevel = enum { OfficialFix, TemporaryFix, Workaround, Unavailable };
pub const ReportConfidence = enum { Unknown, Reasonable, Confirmed };
pub const SecurityRequirement = enum { Low, Medium, High };

const Cvss31MetricTypeValue = union(Cvss31MetricType) {
    AV: enum { N, A, L, P },
    AC: enum { L, H },
    PR: enum { N, L, H },
    UI: enum { N, R },
    S: enum { U, C },
    C: enum { N, L, H },
    I: enum { N, L, H },
    A: enum { N, L, H },
    E: enum { X, U, P, F, H },
    RL: enum { X, O, T, W, U },
    RC: enum { X, U, R, C },
    CR: enum { X, L, M, H },
    IR: enum { X, L, M, H },
    AR: enum { X, L, M, H },
    MAV: enum { X, N, A, L, P },
    MAC: enum { X, H, L },
    MPR: enum { X, N, L, H },
    MUI: enum { X, N, R },
    MS: enum { X, U, C },
    MC: enum { X, N, L, H },
    MI: enum { X, N, L, H },
    MA: enum { X, N, L, H },
};
// zig fmt: on

pub const Cvss31MetricDef = struct {
    is_read: bool = false,
    metric_type: Cvss31MetricType,
    required: bool,
};

pub const Cvss31Metric = struct {
    value: Cvss31MetricTypeValue,
    test_metric_type: if (@import("builtin").mode == .Debug) Cvss31MetricType else void = undefined, // TODO I no longer need this one, but I could use
    test_value: if (@import("builtin").mode == .Debug) []const u8 else void = undefined,
    // weight: f32,
};

// TODO pass by reference
fn getMetric(metric: Cvss31MetricType, cvss_metrics: []Cvss31Metric) ?Cvss31Metric {
    for (cvss_metrics) |cvss_metric| {
        // TODO this one is not working
        // if (@as(@TypeOf(metric), metric) == @as(@TypeOf(cvss_metric.value), cvss_metric.value)) {
        // if (metric == cvss_metric.value) {
        if (metric == @as(Cvss31MetricType, cvss_metric.value)) {
            util.debug("metric {any}", .{metric});
            return cvss_metric;
        }
    }
    return null;
}

// TODO pass by reference
fn getMetricWeight(metric: Cvss31MetricType, cvss_metrics: []Cvss31Metric) f16 {
    // std.log.debug("{any}", .{cvss_metrics});
    const s = if (getMetric(Cvss31MetricType.S, cvss_metrics)) |s|
        switch (s.value) {
            .S => |sv| sv,
            else => |v| util.fatal("S metric is required :) {any}", .{v}),
        }
    else
        util.fatal("S metric is required", .{});
    return if (getMetric(metric, cvss_metrics)) |v| switch (v.value) {
        Cvss31MetricType.AV => |av| switch (av) {
            .N => 0.85,
            .A => 0.62,
            .L => 0.55,
            .P => 0.2,
        },
        Cvss31MetricType.AC => |ac| switch (ac) {
            .L => 0.44,
            .H => 0.77,
        },
        Cvss31MetricType.PR => |pr| {
            return switch (s) {
                .U => switch (pr) {
                    .N => 0.85,
                    .L => 0.62,
                    .H => 0.27,
                },
                .C => switch (pr) {
                    .N => 0.85,
                    .L => 0.68,
                    .H => 0.5,
                },
            };
        },
        Cvss31MetricType.UI => |ui| switch (ui) {
            .N => 0.85,
            .R => 0.62,
        },
        Cvss31MetricType.S => switch (s) {
            .U => 6.42,
            .C => 7.52,
        }, //6.42, 7.52
        Cvss31MetricType.C => |c| switch (c) {
            .N => 0,
            .L => 0.22,
            .H => 0.56,
        }, //0, 0.22, 0.56
        Cvss31MetricType.I => |i| switch (i) {
            .N => 0,
            .L => 0.22,
            .H => 0.56,
        }, //0, 0.22, 0.56
        Cvss31MetricType.A => |a| switch (a) {
            .N => 0,
            .L => 0.22,
            .H => 0.56,
        }, //0, 0.22, 0.56
        Cvss31MetricType.E => |e| switch (e) {
            .X => 1,
            .U => 0.91,
            .P => 0.94,
            .F => 0.97,
            .H => 1,
        }, //1, 0.91, 0.94, 0.97, 1
        Cvss31MetricType.RL => |rl| switch (rl) {
            .X => 1,
            .O => 0.95,
            .T => 0.96,
            .W => 0.97,
            .U => 1,
        }, //1, 0.95, 0.96, 0.97, 1
        Cvss31MetricType.RC => |rc| switch (rc) {
            .X => 1,
            .U => 0.92,
            .R => 0.96,
            .C => 1,
        }, //1, 0.92, 0.96, 1
        Cvss31MetricType.CR => |cr| switch (cr) {
            .X => 1,
            .L => 0.5,
            .M => 1,
            .H => 1.5,
        }, //1, 0.5, 1, 1.5
        Cvss31MetricType.IR => |ir| switch (ir) {
            .X => 1,
            .L => 0.5,
            .M => 1,
            .H => 1.5,
        }, //1, 0.5, 1, 1.5
        Cvss31MetricType.AR => |ar| switch (ar) {
            .X => 1,
            .L => 0.5,
            .M => 1,
            .H => 1.5,
        }, //1, 0.5, 1, 1.5
        Cvss31MetricType.MAV => |mav| switch (mav) {
            .X => getMetricWeight(Cvss31MetricType.AV, cvss_metrics),
            .N => 0.85,
            .A => 0.62,
            .L => 0.55,
            .P => 0.2,
        }, //0, 0.85, 0.62, 0.55, 0.2
        Cvss31MetricType.MAC => |mac| switch (mac) {
            .X => getMetricWeight(Cvss31MetricType.AC, cvss_metrics),
            .H => 0.44,
            .L => 0.77,
        }, //0, 0.44, 0.77
        Cvss31MetricType.MPR => |mpr| {
            const mss = if (getMetric(Cvss31MetricType.MS, cvss_metrics)) |ms| switch (ms.value) {
                .MS => |ms1| switch (ms1) {
                    .X => s,
                    .U => .U,
                    .C => .C,
                },
                else => s,
            } else s;

            const pr = if (getMetric(Cvss31MetricType.PR, cvss_metrics)) |pr2| switch (pr2.value) {
                .PR => |pr1| pr1,
                else => util.fatal("PR is a required metric", .{}),
            } else util.fatal("PR is a required metric", .{});

            return switch (mss) {
                .U => switch (mpr) { // TODO!!!
                    .X => switch (pr) {
                        .N => 0.85,
                        .L => 0.62,
                        .H => 0.27,
                    }, //PR
                    .N => 0.85,
                    .L => 0.62,
                    .H => 0.27,
                },
                .C => switch (mpr) { // TODO!!!
                    .X => switch (pr) {
                        .N => 0.85,
                        .L => 0.68,
                        .H => 0.5,
                    }, //PR
                    .N => 0.85,
                    .L => 0.68,
                    .H => 0.5,
                },
            };
        }, //0.85, 0.62, 0.27, 0.85, 0.68, 0.5
        Cvss31MetricType.MUI => |mui| switch (mui) {
            .X => getMetricWeight(Cvss31MetricType.UI, cvss_metrics),
            .N => 0.85,
            .R => 0.62,
        }, //0, 0.85, 0.62
        Cvss31MetricType.MS => |ms| switch (ms) {
            .X => getMetricWeight(Cvss31MetricType.S, cvss_metrics),
            .U => 6.42,
            .C => 7.52,
        }, //0, 6.42, 7.52
        Cvss31MetricType.MC => |mc| switch (mc) {
            .X => getMetricWeight(Cvss31MetricType.C, cvss_metrics),
            .N => 0,
            .L => 0.22,
            .H => 0.56,
        }, //0, 0, 0.22, 0.56
        Cvss31MetricType.MI => |mi| switch (mi) {
            .X => getMetricWeight(Cvss31MetricType.I, cvss_metrics),
            .N => 0,
            .L => 0.22,
            .H => 0.56,
        }, //0, 0, 0.22, 0.56
        Cvss31MetricType.MA => |ma| switch (ma) {
            .X => getMetricWeight(Cvss31MetricType.A, cvss_metrics),
            .N => 0,
            .L => 0.22,
            .H => 0.56,
        }, //0, 0, 0.22, 0.56
    } else 123; // TODO
}

const Cvss31_def = struct {
    name: []const u8,
    is_required: bool = false,
    is_read: bool = false,
};

fn gen_cvss31_definitions() []Cvss31_def {
    var defs: [std.meta.fieldNames(CVSS31).len]Cvss31_def = undefined;

    inline for (comptime std.meta.fields(CVSS31), 0..) |field, i| {
        // std.meta.fields(comptime T: type)
        // std.meta.fieldInfo(CVSS31, )
        defs[i] = .{
            .name = field.name,
            .is_required = field.default_value != null,
        };

        // sum += @field(my_struct, field_name);
    }
    return &defs;
}

pub const cvss31_definitions: []const Cvss31MetricDef = &.{
    .{ .metric_type = Cvss31MetricType.AV, .required = true },
    .{ .metric_type = Cvss31MetricType.AC, .required = true },
    .{ .metric_type = Cvss31MetricType.PR, .required = true },
    .{ .metric_type = Cvss31MetricType.UI, .required = true },
    .{ .metric_type = Cvss31MetricType.S, .required = true },
    .{ .metric_type = Cvss31MetricType.C, .required = true },
    .{ .metric_type = Cvss31MetricType.I, .required = true },
    .{ .metric_type = Cvss31MetricType.A, .required = true },
    .{ .metric_type = Cvss31MetricType.E, .required = false },
    .{ .metric_type = Cvss31MetricType.RL, .required = false },
    .{ .metric_type = Cvss31MetricType.RC, .required = false },
    .{ .metric_type = Cvss31MetricType.CR, .required = false },
    .{ .metric_type = Cvss31MetricType.IR, .required = false },
    .{ .metric_type = Cvss31MetricType.AR, .required = false },

    .{ .metric_type = Cvss31MetricType.MAV, .required = false },
    .{ .metric_type = Cvss31MetricType.MAC, .required = false },
    .{ .metric_type = Cvss31MetricType.MPR, .required = false },
    .{ .metric_type = Cvss31MetricType.MUI, .required = false },
    .{ .metric_type = Cvss31MetricType.MS, .required = false },
    .{ .metric_type = Cvss31MetricType.MC, .required = false },
    .{ .metric_type = Cvss31MetricType.MI, .required = false },
    .{ .metric_type = Cvss31MetricType.MA, .required = false },
};

fn stringToEnumFirstChar(enum_type: type, str: []const u8) !enum_type {
    inline for (@typeInfo(enum_type).Enum.fields) |field| {
        if (std.mem.eql(u8, field.name[0..1], str)) {
            return @field(enum_type, field.name);
        }
    }
    return types.CvssParseError.UnknownMetricValue;
}

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

pub fn score(cvss: []const u8) !types.CvssScore {
    const metrics = try parseCvss31Metrics1(cvss);
    return scoreCvss31(metrics);
}

fn round_up1(x: f32) f32 {
    const factor = 10.0;
    return std.math.ceil(x * factor) / factor;
}

// TODO pass by reference
fn scoreCvss31(cvss: CVSS31) !types.CvssScore {
    const exploitability_coefficient = 8.22;
    const scope_coefficient = 1.08;

    const av: f32 = switch (cvss.attack_vector) {
        .Network => 0.85,
        .Adjacent => 0.62,
        .Local => 0.55,
        .Physical => 0.2,
    };

    const c: f32 = switch (cvss.confidentiality) {
        .High => 0.56,
        .Low => 0.22,
        .None => 0.0,
    };

    const i: f32 = switch (cvss.integrity) {
        .High => 0.56,
        .Low => 0.22,
        .None => 0.0,
    };

    const a: f32 = switch (cvss.availability) {
        .High => 0.56,
        .Low => 0.22,
        .None => 0.0,
    };

    const s: f32 = switch (cvss.scope) {
        .Changed => 7.52,
        .Unchanged => 6.42,
    };

    const ac: f32 = switch (cvss.attack_complexity) {
        .High => 0.44,
        .Low => 0.77,
    };

    const pr: f32 = switch (cvss.scope) {
        .Unchanged => switch (cvss.privileges_required) {
            .None => 0.85,
            .Low => 0.62,
            .High => 0.27,
        },
        .Changed => switch (cvss.privileges_required) {
            .None => 0.85,
            .Low => 0.68,
            .High => 0.5,
        },
    };

    const ui: f32 = switch (cvss.user_interaction) {
        .None => 0.85,
        .Required => 0.62,
    };

    const iss = (1 - ((1 - c) * (1 - i) * (1 - a)));

    const impact: f32 = switch (cvss.scope) {
        .Unchanged => s * iss,
        .Changed => s * (iss - 0.029) - 3.25 * std.math.pow(f32, iss - 0.02, 15),
    };

    const exploitability: f32 = exploitability_coefficient * av * ac * pr * ui;
    const base_score: f32 = if (impact <= 0)
        0.0
    else switch (cvss.scope) {
        .Unchanged => round_up1(@min(impact + exploitability, 10.0)), // todo rounding
        .Changed => round_up1(@min(scope_coefficient * (impact + exploitability), 10.0)), // todo rounding
    };

    const e: f32 = if (cvss.exploit_code_maturity) |ecm| switch (ecm) {
        .Unproven => 0.91,
        .ProofOfConcept => 0.94,
        .Functional => 0.97,
        .High => 1.0,
    } else 1.0;

    const rl: f32 = if (cvss.remediation_level) |rl| switch (rl) {
        .OfficialFix => 0.95,
        .TemporaryFix => 0.96,
        .Workaround => 0.97,
        .Unavailable => 1.0,
    } else 1.0;

    const rc: f32 = if (cvss.report_confidence) |rc| switch (rc) {
        .Unknown => 0.92,
        .Reasonable => 0.96,
        .Confirmed => 1.0,
    } else 1.0;

    const temporal_score: f32 = base_score * e * rl * rc;

    const mc: f32 = if (cvss.modified_confidentiality) |mc| switch (mc) {
        .None => 0.0,
        .Low => 0.22,
        .High => 0.56,
    } else c;

    const cr: f32 = if (cvss.confidentiality_requirement) |cr| switch (cr) {
        .Low => 0.5,
        .Medium => 1.0,
        .High => 1.5,
    } else 1.0;

    const mi: f32 = if (cvss.modified_integrity) |mi| switch (mi) {
        .None => 0.0,
        .Low => 0.22,
        .High => 0.56,
    } else i;

    const ir: f32 = if (cvss.integrity_requirement) |ir| switch (ir) {
        .Low => 0.5,
        .Medium => 1.0,
        .High => 1.5,
    } else 1.0;

    const ma: f32 = if (cvss.modified_availability) |ma| switch (ma) {
        .None => 0.0,
        .Low => 0.22,
        .High => 0.56,
    } else a;

    const ar: f32 = if (cvss.availability_requirement) |ar| switch (ar) {
        .Low => 0.5,
        .Medium => 1.0,
        .High => 1.5,
    } else 1.0;

    const miss: f32 = @min(1 - ((1 - mc * cr) * (1 - mi * ir) * (1 - ma * ar)), 0.915);

    const ms: f32 = if (cvss.modified_scope) |ms| switch (ms) {
        .Unchanged => 6.42,
        .Changed => 7.52,
    } else s;

    const mav: f32 = if (cvss.modified_attack_vector) |mav| switch (mav) {
        .Network => 0.85,
        .Adjacent => 0.62,
        .Local => 0.55,
        .Physical => 0.2,
    } else av;

    const mac: f32 = if (cvss.modified_attack_complexity) |mac| switch (mac) {
        .High => 0.44,
        .Low => 0.77,
    } else ac;

    const mod_scope = if (cvss.modified_scope) |mod_scope| mod_scope else cvss.scope;
    const mod_priv = if (cvss.modified_privileges_required) |mod_priv| mod_priv else cvss.privileges_required;

    const mpr: f32 = switch (mod_scope) {
        .Unchanged => switch (mod_priv) {
            .None => 0.85,
            .Low => 0.62,
            .High => 0.27,
        },
        .Changed => switch (mod_priv) {
            .None => 0.85,
            .Low => 0.68,
            .High => 0.5,
        },
    };

    const mui: f32 = if (cvss.modified_user_interaction) |mui| switch (mui) {
        .None => 0.85,
        .Required => 0.62,
    } else ui;

    const modified_impact: f32 = if (cvss.modified_scope == .Unchanged or (cvss.modified_scope == null and cvss.scope == .Unchanged))
        ms * miss
    else
        ms * (miss - 0.029) - 3.25 * std.math.pow(f32, miss * 0.9731 - 0.02, 13);

    const modified_exploitability: f32 = exploitability_coefficient * mav * mac * mpr * mui;
    // TODO continue here :)

    const env_score: f32 = if (modified_impact <= 0)
        0.0
    else if (cvss.modified_scope != null and cvss.modified_scope == .Unchanged or (cvss.modified_scope == null and cvss.scope == .Unchanged))
        round_up1(round_up1(@min((modified_impact + modified_exploitability), 10)) * e * rl * rc)
    else
        round_up1(round_up1(@min(scope_coefficient * (modified_impact + modified_exploitability), 10)) * e * rl * rc);

    util.debug("base_score: {d:.2}", .{base_score});
    util.debug("iss: {d:.2}", .{iss});
    util.debug("impact: {d:.2}", .{impact});
    util.debug("exploitability: {d:.2}", .{exploitability});
    util.debug("temporal_score: {d:.2}", .{temporal_score});
    util.debug("miss: {d:.2}", .{miss});
    util.debug("modified_impact: {d:.2}", .{modified_impact});
    util.debug("modified_exploitability: {d:.2}", .{modified_exploitability});
    util.debug("env_score: {d:.2}", .{env_score});
    return types.CvssScore{ .score = base_score, .level = types.CVSS_LEVEL.NONE };
}

fn parseCvss31Metrics1(cvss_string: []const u8) !CVSS31 {
    var metrics = std.ArrayList(Cvss31Metric).init(std.heap.page_allocator);

    var cvss = CVSS31{
        .attack_vector = .Network,
        .attack_complexity = .Low,
        .privileges_required = .None,
        .user_interaction = .None,
        .scope = .Unchanged,
        .confidentiality = .None,
        .integrity = .None,
        .availability = .None,
    };

    const defs = gen_cvss31_definitions();
    util.debug("{s}\r\n", .{defs[defs.len - 1].name});

    const copy_cvss31_def = try std.heap.page_allocator.dupe(Cvss31MetricDef, cvss31_definitions);
    defer std.heap.page_allocator.free(copy_cvss31_def);

    var it = std.mem.tokenizeScalar(u8, cvss_string, '/');
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
                // zig fmt: off
                switch (decl.metric_type) {
                    .AV => cvss.attack_vector                = try stringToEnumFirstChar(AttackVector, metric_value_raw),
                    .AC => cvss.attack_complexity            = try stringToEnumFirstChar(AttackComplexity, metric_value_raw),
                    .PR => cvss.privileges_required          = try stringToEnumFirstChar(PrivilegesRequired, metric_value_raw),
                    .UI => cvss.user_interaction             = try stringToEnumFirstChar(UserInteraction, metric_value_raw),
                    .S  => cvss.scope                        = try stringToEnumFirstChar(Scope, metric_value_raw),
                    .C  => cvss.confidentiality              = try stringToEnumFirstChar(Impact, metric_value_raw),
                    .I  => cvss.integrity                    = try stringToEnumFirstChar(Impact, metric_value_raw),
                    .A  => cvss.availability                 = try stringToEnumFirstChar(Impact, metric_value_raw),

                    .E  => cvss.exploit_code_maturity        = try stringToEnumFirstChar(ExploitCodeMaturity, metric_value_raw),
                    .RL => cvss.remediation_level            = try stringToEnumFirstChar(RemediationLevel, metric_value_raw),
                    .RC => cvss.report_confidence            = try stringToEnumFirstChar(ReportConfidence, metric_value_raw),
                    .CR => cvss.confidentiality_requirement  = try stringToEnumFirstChar(SecurityRequirement, metric_value_raw),
                    .IR => cvss.integrity_requirement        = try stringToEnumFirstChar(SecurityRequirement, metric_value_raw),
                    .AR => cvss.availability_requirement     = try stringToEnumFirstChar(SecurityRequirement, metric_value_raw),
                    .MAV=> cvss.modified_attack_vector       = try stringToEnumFirstChar(AttackVector, metric_value_raw),
                    .MAC=> cvss.modified_attack_complexity   = try stringToEnumFirstChar(AttackComplexity, metric_value_raw),
                    .MPR=> cvss.modified_privileges_required = try stringToEnumFirstChar(PrivilegesRequired, metric_value_raw),
                    .MUI=> cvss.modified_user_interaction    = try stringToEnumFirstChar(UserInteraction, metric_value_raw),
                    .MS => cvss.modified_scope               = try stringToEnumFirstChar(Scope, metric_value_raw),
                    .MC => cvss.modified_confidentiality     = try stringToEnumFirstChar(Impact, metric_value_raw),
                    .MI => cvss.modified_integrity           = try stringToEnumFirstChar(Impact, metric_value_raw),
                    .MA => cvss.modified_availability        = try stringToEnumFirstChar(Impact, metric_value_raw),
                }
                // zig fmt: on

                if (createMetricValue(metric_type_raw.?, metric_value_raw)) |metric_value| {
                    try metrics.append(.{ .test_metric_type = if (@import("builtin").mode == .Debug) metric_type.?, .value = metric_value, .test_value = if (@import("builtin").mode == .Debug) metric_value_raw });
                } else {
                    // std.log.debug("Unexpected value {any}", .{metric_value_raw});
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

    return cvss;
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
                    // std.log.debug("Unexpected value {any}", .{metric_value_raw});
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

test "parse new green test CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const r = try parseCvss31Metrics1(cvss);
    try testing.expectEqual(.Network, r.attack_vector);
}

fn only_score(cvss: []const u8) !f32 {
    const s = try score(cvss);
    return s.score;
}

test "a bunch of scoring tests" {
    try testing.expectEqual(8.8, only_score("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"));
    try testing.expectEqual(5.8, only_score("AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N"));
    try testing.expectEqual(6.4, only_score("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"));
    try testing.expectEqual(3.1, only_score("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"));
}

// test "score green test CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
//     const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
//     const r = try score(cvss);
//     try testing.expectEqual(1, r.CVSS31.score);
// }

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
