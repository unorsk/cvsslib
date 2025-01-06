// const CVSS4_HEADER = "CVSS:4.0";

pub const CvssScore = extern struct {
    score: u8,
    level: CVSS_LEVEL,
};

pub const CVSS = extern struct {
    version: CVSS_VERSION,
    score: CvssScore,
};

pub const CVSS_VERSION = enum(u8) {
    CVSS20,
    CVSS30,
    CVSS31,
    CVSS40,
};

pub const CVSS_LEVEL = enum(u8) {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
};

pub const CvssParseError = error{
    NotCVSSString,
    UnknownMetricValue,
    UnknownMetricName,
    DuplicateMetric,
    MissingRequiredMetrics,
};
