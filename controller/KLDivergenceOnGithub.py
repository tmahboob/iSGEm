import numpy as np
import pandas as pd
from scipy.stats import entropy


def compute_kl_divergence(p, q):
    p = np.asarray(p) + 1e-10  # Avoid division by zero
    q = np.asarray(q) + 1e-10
    return entropy(p, q)


def adjust_alpha(x):
    base_alpha = 2 * np.floor(np.log2(x))
    adjustment = 2 if 10 <= x < 20 else 0
    return base_alpha + adjustment


def gradient_descent_optimal_alpha(data, column, bins, learning_rate=0.01, lambda_kl=0.8, max_iter=2000, tol=1e-2):
    col_min, col_max = data[column].min(), data[column].max()
    initial_alpha = ((col_max - col_min) / col_max) * 10 if col_max != 0 else 2
    alpha = adjust_alpha(initial_alpha)
    prev_kl_div = float(1)

    for t in range(max_iter):
        quantized_data = np.round(data[column] * alpha).astype(np.int32)
        original_hist, bin_edges = np.histogram(data[column], bins=bins, density=True)
        quantized_hist, _ = np.histogram(quantized_data, bins=bin_edges, density=True)

        original_hist /= original_hist.sum()
        quantized_hist /= quantized_hist.sum()

        kl_div = compute_kl_divergence(original_hist, quantized_hist)

        if kl_div < 1.0 and prev_kl_div - kl_div < tol:
            break

        grad = -lambda_kl * np.exp(kl_div)
        alpha -= learning_rate * grad
        prev_kl_div = kl_div

    return alpha, kl_div


# Load dataset
df = pd.read_csv('SV(binary).csv')
df = df[~df.isin([np.nan, np.inf, -np.inf]).any(axis=1)]  # Clean data

# Iterate through columns (1 to 7) and histogram bins [2,4,6,8,10,12,14,16]
results = []
for col_index in range(1, 8):
    column = df.columns[col_index]
    for bins in [2, 4, 6, 8, 10, 12, 14, 16]:
        optimal_alpha, kl_div = gradient_descent_optimal_alpha(df, column, bins)
        results.append([column, bins, optimal_alpha, kl_div])

# Save results to CSV
results_df = pd.DataFrame(results, columns=['Column', 'Bins', 'Optimal Alpha', 'KL Divergence'])
results_df.to_csv('optimal_alpha_results.csv', index=False)
print("Results saved to optimal_alpha_results.csv")
