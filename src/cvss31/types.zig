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
