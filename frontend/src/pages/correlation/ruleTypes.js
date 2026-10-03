export const RULE_TYPES = [
  { value: "threshold", label: "Threshold", hint: "Fire when N events (or N distinct values) occur per group in the window." },
  { value: "sequence", label: "Sequence", hint: "Fire when ordered stages occur in order for the same group." },
  { value: "rare", label: "Rare", hint: "Fire when a group's baseline frequency is below a floor." },
  { value: "beacon", label: "Beacon", hint: "Fire on regular callback intervals (low timing variance)." },
];

export const GROUP_BY_FIELDS = ["src_ip", "dst_ip", "signature_id", "dst_port", "src_port", "proto"];

export function defaultParamsFor(ruleType) {
  switch (ruleType) {
    case "threshold":
      return { count_distinct_field: "" };
    case "sequence":
      return { steps: [{ signature_id: [] }, { signature_id: [] }] };
    case "rare":
      return { baseline_days: 14, frequency_floor: 3 };
    case "beacon":
      return { max_cv: 0.15, min_samples: 5 };
    default:
      return {};
  }
}
