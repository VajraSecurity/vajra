/** Regex fragment matching one range-checked IPv4 octet (0-255), not just digit-counted. */
export const IPV4_OCTET_PATTERN = '(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4_CIDR_REGEX = new RegExp(
  `^${IPV4_OCTET_PATTERN}\\.${IPV4_OCTET_PATTERN}\\.${IPV4_OCTET_PATTERN}\\.${IPV4_OCTET_PATTERN}/(3[0-2]|[12]?[0-9])$`
);

export function isValidIpv4Cidr(value: unknown): value is string {
  return typeof value === 'string' && IPV4_CIDR_REGEX.test(value.trim());
}
