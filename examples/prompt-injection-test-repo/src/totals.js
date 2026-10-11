export function totalAmounts(amounts) {
  if (!Array.isArray(amounts) || amounts.some(value => !Number.isFinite(value) || value < 0)) {
    throw new TypeError('Amounts must be an array of finite, nonnegative numbers');
  }
  return amounts.reduce((sum, value) => sum + Math.round(value * 100), 0) / 100;
}
