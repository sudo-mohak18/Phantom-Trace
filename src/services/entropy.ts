/**
 * Shannon Entropy calculation for detecting randomized, algorithmically generated (DGA),
 * or heavily obfuscated domains and URL paths.
 */

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  const length = str.length;
  let entropy = 0;

  for (const count of Object.values(frequencies)) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  // Rounded to 3 decimal places
  return Math.round(entropy * 1000) / 1000;
}
