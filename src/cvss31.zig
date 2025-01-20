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

pub const Cvss31MetricDef = struct {
    is_read: bool = false,
    metric_type: Cvss31MetricType,
    required: bool,
};

const Cvss31_def = struct {
    name: []const u8,
    is_required: bool = false,
    is_read: bool = false,
};

fn gen_cvss31_definitions() []Cvss31_def {
    var defs: [std.meta.fieldNames(CVSS31).len]Cvss31_def = undefined;

    inline for (comptime std.meta.fields(CVSS31), 0..) |field, i| {
        defs[i] = .{
            .name = field.name,
            .is_required = field.default_value != null,
        };
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
    inline for (@typeInfo(enum_type).@"enum".fields) |field| {
        if (std.mem.eql(u8, field.name[0..1], str)) {
            return @field(enum_type, field.name);
        }
    }
    return types.CvssParseError.UnknownMetricValue;
}

fn stringToEnum(enum_type: type, str: []const u8) ?enum_type {
    inline for (@typeInfo(enum_type).@"enum".fields) |field| {
        if (std.mem.eql(u8, field.name, str)) {
            return @field(enum_type, field.name);
        }
    }
    return null;
}

pub fn score(cvss: []const u8) !types.CvssScore {
    const metrics = try parseCvss31(cvss);
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
        .Unchanged => round_up1(@min(impact + exploitability, 10.0)),
        .Changed => round_up1(@min(scope_coefficient * (impact + exploitability), 10.0)),
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
    return types.CvssScore{ .score = base_score, .level = util.levelFromScore(base_score) };
}

fn parseCvss31(cvss_string: []const u8) !CVSS31 {
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

test "parse duplicate metric CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N";
    const err = parseCvss31(cvss);
    try testing.expectError(types.CvssParseError.DuplicateMetric, err);
}

test "parse missing metricCVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H";
    const err = parseCvss31(cvss);
    try testing.expectError(types.CvssParseError.MissingRequiredMetrics, err);
}

test "parse new green test CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const r = try parseCvss31(cvss);
    try testing.expectEqual(.Network, r.attack_vector);
}

fn only_score(cvss: []const u8) !f32 {
    const s = try score(cvss);
    return s.score;
}

test "a bunch of scoring tests" {
    const s1 = try score("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
    try testing.expectEqual(8.8, s1.score);
    try testing.expectEqual(types.CVSS_LEVEL.HIGH, s1.level);

    const s2 = try score("AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
    try testing.expectEqual(5.8, s2.score);
    try testing.expectEqual(types.CVSS_LEVEL.MEDIUM, s2.level);

    const s3 = try score("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
    try testing.expectEqual(6.4, s3.score);
    try testing.expectEqual(types.CVSS_LEVEL.MEDIUM, s3.level);

    const s4 = try score("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
    try testing.expectEqual(3.1, s4.score);
    try testing.expectEqual(types.CVSS_LEVEL.LOW, s4.level);
}

test "parse green test CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
    const cvss_string = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const cvss = try parseCvss31(cvss_string);

    try testing.expectEqual(.Network, cvss.attack_vector);
    try testing.expectEqual(.Low, cvss.attack_complexity);
    try testing.expectEqual(.Low, cvss.privileges_required);
    try testing.expectEqual(.None, cvss.user_interaction);
    try testing.expectEqual(.Unchanged, cvss.scope);
    try testing.expectEqual(.High, cvss.confidentiality);
    try testing.expectEqual(.High, cvss.integrity);
    try testing.expectEqual(.High, cvss.availability);
}

test "parse simple AV metric unknown value" {
    const cvss = "AV:Z";
    const err = parseCvss31(cvss);
    try testing.expectError(types.CvssParseError.UnknownMetricValue, err);
}
