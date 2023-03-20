export function toHexString(value: number[]): string {
  return value.map((bytes) => bytes.toString(16).padStart(2, "0")).join("");
}
